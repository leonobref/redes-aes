# Servidor.py
import os
import smtplib
from email.message import EmailMessage
import mimetypes
import threading
import socket
import json
import base64
import random
from cripto import RSA_verify

host = 'localhost'
port = 55555

encoding = 'utf-8'
DEBUG = True

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = {} 
nicknames = [] 
user_emails = []
public_keys = {} 
groups = {}

server_email = 'redesaes094@gmail.com'
subject = "Verification Code"
password = 'aggd omav erbs oyjf'

USERS_FILE = "users.json"
GROUPS_FILE = 'groups.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=0)

def load_groups():
    if os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_groups(gp):
    with open(GROUPS_FILE, 'w', encoding='utf-8') as f:
        json.dump(gp, f, indent=0)



public_keys = load_users()  # map nickname -> public_key_pem (string or base64)
# converter strings para bytes se necessário quando usado (o seu código aceita bytes)
for k,v in list(public_keys.items()):
    if isinstance(v, str):
        public_keys[k] = v.encode('utf-8')

groups = load_groups()


def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def cleanup_client(nick):
    print(f"[SERVER] Limpando sessão de {nick}")

    # 1. Fecha o socket
    try:
        clients[nick].close()
    except:
        pass

    # 2. Remove estado temporário
    clients.pop(nick, None)
    public_keys.pop(nick, None)

    if nick in nicknames:
        nicknames.remove(nick)

def send_payload_to_socket(sock, payload_obj):
    pld = json.dumps(payload_obj).encode(encoding)
    sock.send(len(pld).to_bytes(4))
    sock.send(pld)

def handle_create_group(payload, client):
    # payload: { 'group', 'creator', 'members', 'enc_keys' }
    group_name = payload.get('group')
    creator = payload.get('creator')
    members = payload.get('members', [])
    enc_keys = payload.get('enc_keys', {})

    if group_name in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} já existe'})
        return

    if creator not in members:
        members.append(creator)

    valid_members = [m for m in members if m in clients]
    groups[group_name] = {'key': None, 'owner': creator, 'members': valid_members}

    save_groups(groups)

    # encaminha enc_keys (cada enc_key é base64 string) para os membros válidos
    for m in valid_members:
        try:
            c = clients[m]
            member_enc_key = enc_keys.get(m)
            if member_enc_key:
                payload_to_member = {
                    'cmd': '/group_key',
                    'group': group_name,
                    'creator': creator,
                    'members': valid_members,
                    'enc_key': member_enc_key
                }
            else:
                payload_to_member = {
                    'cmd': '/group_info',
                    'group': group_name,
                    'creator': creator
                }
            send_payload_to_socket(c, payload_to_member)
        except KeyError:
            continue

def handle_gsend(payload, client):
    group_name = payload.get('group')
    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    members = groups[group_name]['members']
    # encaminhar payload para todos membros (inclui remetente)
    for m in members:
        if m in clients:
            try:
                send_payload_to_socket(clients[m], payload)
            except:
                continue

def rotate_group_key_and_broadcast(group_name, actor, enc_keys):
    """
    enc_keys: dict member -> base64 encoded encrypted new AES key (string)
    Este util envia /group_key para cada membro segundo enc_keys.
    """
    members = groups[group_name]['members']

    if not isinstance(members, list):
        members = list(members)
        
    for m in members:
        if m in clients:
            try:
                payload_to_member = {
                    'cmd': '/group_key',
                    'group': group_name,
                    'creator': actor,
                    'members': members,
                    'enc_key': enc_keys.get(m)
                }
                send_payload_to_socket(clients[m], payload_to_member)
            except:
                continue

def handle_addmember(payload, client):
    # payload: {'group','actor','new_member','enc_keys'}
    group_name = payload.get('group')
    actor = payload.get('actor')
    new_member = payload.get('new_member')
    enc_keys = payload.get('enc_keys', {})

    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    group = groups[group_name]
    if actor != group['owner']:
        send_payload_to_socket(client, {'cmd':'error','msg':'Apenas o dono pode adicionar membros'})
        return

    if new_member not in clients:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Usuário {new_member} não está online'})
        return

    if new_member in group['members']:
        send_payload_to_socket(client, {'cmd':'error','msg':f'{new_member} já está no grupo'})
        return

    group['members'].append(new_member)
    save_groups(groups)
    # broadcast enc_keys (owner já rotacionou e incluiu todos)
    rotate_group_key_and_broadcast(group_name, actor, enc_keys)

def handle_removemember(payload, client):
    # payload: {'group','actor','remove','enc_keys'}
    group_name = payload.get('group')
    actor = payload.get('actor')
    remove_nick = payload.get('remove')
    enc_keys = payload.get('enc_keys', {})

    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    group = groups[group_name]
    if actor != group['owner']:
        send_payload_to_socket(client, {'cmd':'error','msg':'Apenas o dono pode remover membros'})
        return

    if remove_nick not in group['members']:
        send_payload_to_socket(client, {'cmd':'error','msg':f'{remove_nick} não faz parte do grupo'})
        return

    group['members'] = [m for m in group['members'] if m != remove_nick]
    save_groups(groups)

    # notificar removido (opcional)
    if remove_nick in clients:
        try:
            send_payload_to_socket(clients[remove_nick], {'cmd':'removed','msg':f'Você foi removido do grupo {group_name}'})
        except:
            pass

    # enviar nova chave rotacionada para os restantes (enc_keys deve conter entries para os membros)
    rotate_group_key_and_broadcast(group_name, actor, enc_keys)

def handle_leavegroup(payload, client):
    # payload: {'group','member'}
    group_name = payload.get('group')
    member = payload.get('member')

    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    group = groups[group_name]
    if member not in group['members']:
        send_payload_to_socket(client, {'cmd':'error','msg':'Você não está nesse grupo.'})
        return

    # remove
    group['members'] = [m for m in group['members'] if m != member]

    # se vazio -> apaga
    if not group['members']:
        del groups[group_name]
        save_groups(groups)
        return

    if member == group['owner']:
        remaining = [m for m in group['members'] if m != member]

        if not remaining:
            del groups[group_name]
            save_groups(groups)
            return

        new_owner = remaining[0]
        group['owner'] = new_owner
        group['members'] = remaining
        save_groups(groups)

        if new_owner in clients:
            try:
                send_payload_to_socket(clients[new_owner], {'cmd': 'become_owner', 'group': group_name})
            except:
                pass

    # caso membro comum saiu -> notificar owner que precisa rotacionar
    save_groups(groups)
    owner = group['owner']
    if owner in clients:
        try:
            send_payload_to_socket(clients[owner], {'cmd':'need_rotate','group':group_name,'left_member':member})
        except:
            pass

def handle_rotategroup(payload, client):
    # payload: {'group','actor','enc_keys'}
    group_name = payload.get('group')
    actor = payload.get('actor')
    enc_keys = payload.get('enc_keys', {})

    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    group = groups[group_name]
    if actor != group['owner']:
        send_payload_to_socket(client, {'cmd':'error','msg':'Apenas o dono pode rotacionar a chave'})
        return

    rotate_group_key_and_broadcast(group_name, actor, enc_keys)

def handle(client):
    while True:
        try:
            tam_pld = int.from_bytes(recvall(client, 4))
            payload = json.loads(recvall(client, tam_pld).decode(encoding))

            cmd = payload.get('cmd')

            if cmd == '/add':
                # pedido de chave pública de outro usuario
                dest = payload.get('dest')
                if dest in public_keys:
                    if DEBUG:
                        print(f"\n[DEBUG] Requisção de chave pública de {dest}")
                        print(f"[DEBUG] Chave pública: {public_keys[dest]}\n")
                    payload_out = {'cmd':'/add','dest': dest, 'key': base64.b64encode(public_keys[dest]).decode(encoding)}
                else:
                    payload_out = {'cmd':'/add'}  # indica inexistência
                send_payload_to_socket(client, payload_out)

            elif cmd == '/send':
                # 1-a-1
                dest = payload.get('dest')
                if dest in clients:
                    send_payload_to_socket(clients[dest], payload)
                else:
                    send_payload_to_socket(client, {'cmd':'error','dest': dest, 'msg':'Este usuário não existe mais'})

            elif cmd == '/creategroup':
                handle_create_group(payload, client)

            elif cmd == '/gsend':
                handle_gsend(payload, client)

            elif cmd == '/addmember':
                handle_addmember(payload, client)

            elif cmd == '/removemember':
                handle_removemember(payload, client)

            elif cmd == '/leavegroup':
                handle_leavegroup(payload, client)

            elif cmd == '/rotategroup':
                handle_rotategroup(payload, client)
            
            elif cmd == "/disconnect":
                nick = payload['sender']
                cleanup_client(nick)
                break

            else:
                send_payload_to_socket(client, {'cmd':'error','msg':'Comando desconhecido'})

        except Exception as e:
            # cliente desconectou — limpa estruturas e notifica proprietários se necessário
            if DEBUG:
                print(f"[SERVER] handler exception: {e}")
            index = None
            for nick, c in clients.items():
                if c == client:
                    index = nick
                    break

            if index:
                try:
                    c = clients[index]
                    c.close()
                except:
                    pass

                del clients[index]
                if index in public_keys:
                    del public_keys[index]
                if index in nicknames:
                    nicknames.remove(index)

                # remover index de todos os grupos e notificar owners
                to_delete = []
                for g, info in list(groups.items()):
                    if index in info['members']:
                        info['members'] = [m for m in info['members'] if m != index]
                        # se o index era owner:
                        if info['owner'] == index:
                            if len(info['members']) == 0:
                                to_delete.append(g)
                            else:
                                new_owner = info['members'][0]
                                groups[g] = {'members': info['members'], 'owner': new_owner, 'key': None}
                                try:
                                    send_payload_to_socket(clients[new_owner], {'cmd':'become_owner','group':g})
                                except:
                                    pass
                        else:
                            # notifica owner que alguém saiu/foi desconectado e que precisa rotacionar
                            try:
                                send_payload_to_socket(clients[info['owner']], {'cmd':'need_rotate','group':g,'left_member':index})
                            except:
                                pass
                for g in to_delete:
                    del groups[g]
            break

def receive():
    while True:
        client, address = server.accept()
        print(f"\nConectou com {str(address)}")

        challenge = os.urandom(32)
        client.send(len(challenge).to_bytes(4))
        client.send(challenge)

        tam_rsa_public_key = int.from_bytes(recvall(client, 4))
        rsa_public_key = recvall(client, tam_rsa_public_key)

        tam_signature = int.from_bytes(recvall(client, 4))
        signature = recvall(client, tam_signature)

        tam_nickname = int.from_bytes(recvall(client, 4))
        nickname = recvall(client, tam_nickname).decode(encoding)
        nicknames.append(nickname)

        tam_user_email = int.from_bytes(recvall(client, 4))
        user_email = recvall(client, tam_user_email).decode(encoding)
        user_emails.append(user_email)

        verification_code = str(random.randint(100000, 999999))
        
        msg = EmailMessage()
        msg['From'] = server_email
        msg['To'] = user_email
        msg['Subject'] = subject
        msg.set_content("Seu código de verificação é: " + verification_code)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as email:
            email.login(server_email, password)
            email.send_message(msg)
            print("chegueiaqui")

        tam_verification_code_client = int.from_bytes(recvall(client, 4))
        verification_code_client = recvall(client, tam_verification_code_client).decode(encoding)

        if verification_code != verification_code_client:
            client.send('Codigo de verificação Incorreto! Reinicie a Aplicação'.encode(encoding))
            client.close()
            continue

        if RSA_verify(challenge, signature, rsa_public_key):
            if DEBUG:
                print(f"\n[DEBUG] Chave autenticada para o cliente {nickname}")
                print(f"\n[DEBUG] Assinatura: {signature}\n")

            clients[nickname] = client
            public_keys[nickname] = rsa_public_key

            save_users({k: (v.decode('utf-8') if isinstance(v, bytes) else v) for k,v in public_keys.items()})

            client.send('NICK'.encode(encoding))

            print(f"[SERVER] O apelido do cliente é {nickname}")

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
        
        else:
            client.send('ERR_SIGN'.encode(encoding))
            client.close()
            continue

print(f"[SERVER] Servidor está online...")
receive()
