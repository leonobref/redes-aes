# Servidor_k_v5.py
import os
import threading
import socket
import json
import base64
import hashlib
import binascii
import hmac
from cripto import RSA_verify, RSA_decrypt, RSA_keys_generate

from Crypto.PublicKey import RSA  # apenas para persistir a chave do servidor

host = 'localhost'
port = 55555

encoding = 'utf-8'
DEBUG = False

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = {}
nicknames = []
public_keys = {}
groups = {}

# users_db[nickname] = {'salt': salt_hex, 'pwd_hash': hash_hex, 'public_key': pub_pem_bytes}
users_db = {}

PBKDF2_ITERS = 200000

# --- gerar/ler chave RSA do servidor (persistente) ---
SERVER_KEY_FILE = 'server_key.pem'
if os.path.exists(SERVER_KEY_FILE):
    with open(SERVER_KEY_FILE, 'rb') as f:
        server_private_key = RSA.import_key(f.read())
else:
    key = RSA.generate(2048)
    server_private_key = key
    with open(SERVER_KEY_FILE, 'wb') as f:
        f.write(key.export_key())
server_public_key_pem = server_private_key.publickey().export_key()

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_payload_to_socket(sock, payload_obj):
    pld = json.dumps(payload_obj).encode(encoding)
    sock.send(len(pld).to_bytes(4))
    sock.send(pld)

def hash_password_local(password, salt=None, iterations=PBKDF2_ITERS):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return binascii.hexlify(salt).decode('ascii'), binascii.hexlify(dk).decode('ascii')

def rotate_group_key_and_broadcast(group_name, actor, enc_keys):
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

def handle_create_group(payload, client):
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
    for m in members:
        if m in clients:
            try:
                send_payload_to_socket(clients[m], payload)
            except:
                continue

def handle_addmember(payload, client):
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
        send_payload_to_socket(client, {'cmd':'error','msg':f'{new_member} já está no grupo'} )
        return

    group['members'].append(new_member)
    rotate_group_key_and_broadcast(group_name, actor, enc_keys)

def handle_removemember(payload, client):
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

    if remove_nick in clients:
        try:
            send_payload_to_socket(clients[remove_nick], {'cmd':'removed','msg':f'Você foi removido do grupo {group_name}'})
        except:
            pass

    rotate_group_key_and_broadcast(group_name, actor, enc_keys)

def handle_leavegroup(payload, client):
    group_name = payload.get('group')
    member = payload.get('member')

    if group_name not in groups:
        send_payload_to_socket(client, {'cmd':'error','msg':f'Grupo {group_name} não existe'})
        return

    group = groups[group_name]
    if member not in group['members']:
        send_payload_to_socket(client, {'cmd':'error','msg':'Você não está nesse grupo.'})
        return

    group['members'] = [m for m in group['members'] if m != member]

    if not group['members']:
        del groups[group_name]
        return

    if member == group['owner']:
        remaining = [m for m in group['members'] if m != member]

        if not remaining:
            del groups[group_name]
            return

        new_owner = remaining[0]
        group['owner'] = new_owner
        group['members'] = remaining

        if new_owner in clients:
            try:
                send_payload_to_socket(clients[new_owner], {'cmd': 'become_owner', 'group': group_name})
            except:
                pass

    owner = group['owner']
    if owner in clients:
        try:
            send_payload_to_socket(clients[owner], {'cmd':'need_rotate','group':group_name,'left_member':member})
        except:
            pass

def handle_rotategroup(payload, client):
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
                dest = payload.get('dest')
                if dest in public_keys:
                    if DEBUG:
                        print(f"\n[DEBUG] Requisção de chave pública de {dest}")
                        print(f"[DEBUG] Chave pública: {public_keys[dest]}\n")
                    payload_out = {'cmd':'/add','dest': dest, 'key': base64.b64encode(public_keys[dest]).decode(encoding)}
                else:
                    payload_out = {'cmd':'/add'}
                send_payload_to_socket(client, payload_out)

            elif cmd == '/send':
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

            else:
                send_payload_to_socket(client, {'cmd':'error','msg':'Comando desconhecido'})

        except Exception as e:
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

                to_delete = []
                for g, info in list(groups.items()):
                    if index in info['members']:
                        info['members'] = [m for m in info['members'] if m != index]
                        if info['owner'] == index:
                            remaining = [m for m in info['members'] if m != index]

                            if len(remaining) == 0:
                                to_delete.append(g)
                            else:
                                new_owner = remaining[0]
                                info['owner'] = new_owner
                                info['members'] = remaining

                                try:
                                    send_payload_to_socket(clients[new_owner], {'cmd': 'become_owner', 'group': g})
                                except:
                                    pass
                        else:
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

        # challenge (como antes)
        challenge = os.urandom(32)
        client.send(len(challenge).to_bytes(4))
        client.send(challenge)

        # envia também a chave pública do SERVIDOR (para o cliente cifrar dados sensíveis no registro)
        client.send(len(server_public_key_pem).to_bytes(4))
        client.send(server_public_key_pem)

        tam_rsa_public_key = int.from_bytes(recvall(client, 4))
        rsa_public_key = recvall(client, tam_rsa_public_key)

        tam_signature = int.from_bytes(recvall(client, 4))
        signature = recvall(client, tam_signature)

        tam_nickname = int.from_bytes(recvall(client, 4))
        nickname = recvall(client, tam_nickname).decode(encoding)

        # agora o servidor espera apenas a ação (register/login) — sem senha direto
        tam_cred = int.from_bytes(recvall(client, 4))
        cred_b = recvall(client, tam_cred)
        try:
            cred = json.loads(cred_b.decode(encoding))
        except:
            client.send('ERR_CRED'.encode(encoding))
            client.close()
            continue

        action = cred.get('action')

        # valida assinatura do challenge com a chave pública enviada (garante posse da chave privada do cliente)
        if not RSA_verify(challenge, signature, rsa_public_key):
            client.send('ERR_SIGN'.encode(encoding))
            client.close()
            continue

        # FLUXO: REGISTER — agora pede salt + dk_enc (dk cifrado com chave pública do servidor)
        if action == 'register':
            # pede dados de registro
            send_payload_to_socket(client, {'cmd':'request_password'})

            # recebe JSON com {'salt': <hex>, 'dk_enc': <base64>}
            tam_pwd = int.from_bytes(recvall(client, 4))
            pwd_b = recvall(client, tam_pwd)
            try:
                pwd_obj = json.loads(pwd_b.decode(encoding))
                salt_hex = pwd_obj.get('salt', '')
                dk_enc_b64 = pwd_obj.get('dk_enc', '')
            except:
                client.send('ERR_CRED'.encode(encoding))
                client.close()
                continue

            if not salt_hex or not dk_enc_b64:
                client.send('ERR_CRED'.encode(encoding))
                client.close()
                continue

            if nickname in users_db:
                client.send('ERR_EXISTS'.encode(encoding))
                client.close()
                continue

            # decifra dk com a chave privada do servidor
            try:
                dk_enc = base64.b64decode(dk_enc_b64)
                dk = RSA_decrypt(dk_enc, server_private_key)  # retorna bytes
                dk_hex = binascii.hexlify(dk).decode('ascii')
            except Exception as e:
                if DEBUG:
                    print(f"[SERVER] falha ao decifrar dk: {e}")
                client.send('ERR_CRED'.encode(encoding))
                client.close()
                continue

            # armazena salt + derived key (hex) — sem nunca ter recebido a senha em texto
            users_db[nickname] = {'salt': salt_hex, 'pwd_hash': dk_hex, 'public_key': rsa_public_key}

            # registra cliente como online
            clients[nickname] = client
            public_keys[nickname] = rsa_public_key
            nicknames.append(nickname)
            client.send('NICK'.encode(encoding))
            print(f"[SERVER] Usuário registrado e conectado: {nickname}")

            # notificar só quem já tinha adicionado esse usuário previamente:
            for other_nick, sock in clients.items():
                if other_nick == nickname:
                    continue
                try:
                    payload = {'cmd':'/update_pubkey', 'user': nickname, 'key': base64.b64encode(rsa_public_key).decode(encoding)}
                    send_payload_to_socket(sock, payload)
                except:
                    pass

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
            continue

        # FLUXO: LOGIN usando prova HMAC sobre derived key (PBKDF2)
        elif action == 'login':
            if nickname not in users_db:
                send_payload_to_socket(client, {'cmd':'auth_failed', 'msg':'Usuário não existe. Tente novamente.'})
                continue

            # envia salt para o cliente (server já tem stored derived key)
            salt_hex = users_db[nickname]['salt']
            send_payload_to_socket(client, {'cmd':'auth_challenge', 'salt': salt_hex})

            # agora o cliente deve enviar a prova: {'proof': hex}
            tam_proof = int.from_bytes(recvall(client, 4))
            proof_b = recvall(client, tam_proof)
            try:
                proof_obj = json.loads(proof_b.decode(encoding))
                proof = proof_obj.get('proof', '')
            except:
                client.send('ERR_CRED'.encode(encoding))
                client.close()
                continue

            # server calcula expected = HMAC_SHA256(stored_dk_bytes, challenge)
            stored_hash_hex = users_db[nickname]['pwd_hash']
            stored_dk = binascii.unhexlify(stored_hash_hex.encode('ascii'))
            expected = hmac.new(stored_dk, challenge, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected, proof):
                send_payload_to_socket(client, {'cmd': 'auth_failed', 'msg': 'Senha incorreta. Tente novamente.'})
                continue

            # sucesso: registra cliente online, atualiza public_key
            users_db[nickname]['public_key'] = rsa_public_key
            clients[nickname] = client
            public_keys[nickname] = rsa_public_key
            nicknames.append(nickname)
            client.send('NICK'.encode(encoding))
            print(f"[SERVER] Usuário autenticado e conectado: {nickname}")

            # notificar só quem já tinha adicionado esse usuário previamente:
            for other_nick, sock in clients.items():
                if other_nick == nickname:
                    continue
                try:
                    payload = {'cmd':'/update_pubkey', 'user': nickname, 'key': base64.b64encode(rsa_public_key).decode(encoding)}
                    send_payload_to_socket(sock, payload)
                except:
                    pass

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
            continue

        else:
            client.send('ERR_ACTION'.encode(encoding))
            client.close()
            continue

print(f"[SERVER] Servidor está online...")
receive()
