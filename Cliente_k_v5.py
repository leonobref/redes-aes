# Cliente.py
import socket
import threading
import json
import base64
import cripto

encoding = 'utf-8'
DEBUG = True
LOGIN = False

nickname = input("Insira seu apelido: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 55555))

private_key, public_key = cripto.RSA_keys_generate()

public_keys = {}
group_keys = {} 
groups = {}       

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def receber():
    global LOGIN
    while True:
        try:
            if LOGIN:
                tam_pld = int.from_bytes(recvall(client, 4))
                payload = json.loads(recvall(client, tam_pld).decode(encoding))

                cmd = payload.get('cmd')

                if cmd == '/add':
                    if len(payload) == 1:
                        print("\nDestinatário não existe")
                        continue
                    key = base64.b64decode(payload['key'])
                    public_keys[payload['dest']] = key
                    if DEBUG:
                        print(f"\n[DEBUG] Chave pública recebida: {payload['dest']} -> {key}\n")

                elif cmd == '/send':
                    sig = payload.get('signature')
                    if sig is None:
                        continue

                    sig = base64.b64decode(sig)

                    if DEBUG:
                        print(f"\n[DEBUG] Assinatura: {sig}")
                    
                    pld_to_verify = dict(payload)
                    del pld_to_verify['signature']
                    to_verify = json.dumps(pld_to_verify, sort_keys=True).encode(encoding)
                    sender_pub = public_keys.get(pld_to_verify.get('sender'))

                    if not sender_pub or not cripto.RSA_verify(to_verify, sig, sender_pub):
                        continue

                    iv = base64.b64decode(payload['iv'])
                    tag = base64.b64decode(payload['tag'])
                    aes_key_encrypted = base64.b64decode(payload['aes_key_encrypted'])
                    cipherText = base64.b64decode(payload['ciphertext'])
                    aes_key = cripto.RSA_decrypt(aes_key_encrypted, private_key)
                    mensagem = cripto.AES_decrypt(cipherText, aes_key, iv, tag)

                    if not mensagem:
                        continue

                    if DEBUG:
                        print(f"\n[DEBUG] tag: {tag}")
                        print(f"\n[DEBUG] Texto cifrado recebido: {cipherText}")
                        print(f"\n[DEBUG] Chave AES encriptada: {aes_key_encrypted}")
                        print(f"\n[DEBUG] Chave AES: {aes_key}\n")

                    print(mensagem)

                elif cmd == '/group_key':
                    enc_key_b64 = payload.get('enc_key')
                    group_name = payload.get('group')
                    creator = payload.get('creator')
                    members = payload.get('members')
                    if enc_key_b64 and group_name:
                        enc_key = base64.b64decode(enc_key_b64)
                        aes_key = cripto.RSA_decrypt(enc_key, private_key)

                        groups[group_name] = list(members)
                        group_keys[group_name] = aes_key

                        if DEBUG:
                            print(f"\n[DEBUG] Chave de grupo encriptada: {enc_key}")
                            print(f"\n[DEBUG] Chave de grupo recebida: {aes_key}\n")
                    
                        print(f"[CLIENT] Membros atuais: {', '.join(map(str, members))}")

                elif cmd == '/group_info':
                    group_name = payload.get('group')
                    print(f"[CLIENT] Info: você faz parte do grupo {group_name} (sem chave enviada).")

                elif cmd == '/gsend':
                    group_name = payload.get('group')
                    iv = base64.b64decode(payload['iv'])
                    tag = base64.b64decode(payload['tag'])
                    cipherText = base64.b64decode(payload['ciphertext'])
                    aes_key = group_keys.get(group_name)
                    if not aes_key:
                        print(f"\nVocê não tem a chave para o grupo {group_name}.")
                        continue

                    mensagem = cripto.AES_decrypt(cipherText, aes_key, iv, tag)
                    if not mensagem:
                        continue

                    if DEBUG:
                        print(f"\n[DEBUG] tag: {tag}")
                        print(f"\n[DEBUG] Texto do grupo [{group_name}] encriptado recebido:\n{cipherText}\n")
 
                    print(mensagem)

                elif cmd == 'need_rotate':
                    group = payload.get('group')
                    left = payload.get('left_member')
                    print(f"[CLIENT] Membro {left} saiu do grupo {group}.")
                    new_aes = cripto.AES_key_generate()
                    enc_keys = {}

                    members = groups[group]
                    missing = [m for m in members if m not in public_keys]
                    if missing:
                        print(f"Faltam chaves públicas: {missing}")
                        continue

                    new_aes = cripto.AES_key_generate()
                    enc_keys = {}

                    for m in members:
                        enc = cripto.RSA_encrypt(new_aes, public_keys[m])
                        enc_keys[m] = base64.b64encode(enc).decode(encoding)

                    group_keys[group] = new_aes
                    payload = {
                        'cmd':'/rotategroup',
                        'group':group,
                        'actor':nickname,
                        'enc_keys':enc_keys
                        }
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    print(f"[CLIENT] Pedido de rotação de chave para {group} enviado.")
                    continue


                elif cmd == 'become_owner':
                    grp = payload.get('group')
                    print(f"[CLIENT] Você agora é dono do grupo {grp}. Rode /rotategroup {grp}.")

                elif cmd == 'removed':
                    print(f"[CLIENT] {payload.get('msg')}")

                elif cmd == 'error':
                    print(f"[CLIENT] ERRO: {payload.get('msg')}")

                else:
                    print(f"[CLIENT] Payload desconhecido: {payload}")

            else:

                # Receber challenge
                tam_challenge = int.from_bytes(recvall(client, 4))
                challenge = recvall(client, tam_challenge)

                # Criar assinatura com a chave RSA privada 
                signature = cripto.RSA_sign(challenge, private_key)

                if DEBUG:
                    print(f"\n[DEBUG] Assinatura: {signature}\n")

                # Enviar chave RSA pública
                client.send(len(public_key).to_bytes(4))
                client.send(public_key)

                # Enviar assinatura
                client.send(len(signature).to_bytes(4))
                client.send(signature)

                # Enviar nickname
                encode_nick = nickname.encode(encoding)
                client.send(len(encode_nick).to_bytes(4))
                client.send(encode_nick)

                mensagem = client.recv(1024).decode(encoding)
                if mensagem == 'NICK':
                    LOGIN = True
                    public_keys[nickname] = public_key
                    print("\nComandos:")
                    print("/add <dest>")
                    print("/send <dest> <msg>")
                    print("/creategroup <group> <member1,member2,...>")
                    print("/gsend <group> <msg>")
                    print("/addmember <group> <user>")
                    print("/removemember <group> <user>")
                    print("/leavegroup <group>")
                    print("/rotategroup <group>\n")
                else:
                    print(mensagem)
                    client.close()
                    break

        except Exception as e:
            print(f"[CLIENT] Falha ao receber a mensagem: {e}")
            client.close()
            break

def escrever():
    global LOGIN
    while True:
        try:
            if LOGIN:
                text = input('')
                if not text:
                    continue

                if text.startswith('/add '):
                    split_text = text.split(' ', 1)
                    dest = split_text[1].strip()
                    
                    payload = {
                        'cmd':'/add',
                        'dest':dest
                        }
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    continue

                if text.startswith('/1d '):
                    print(public_keys)
                    continue

                if text.startswith('/2d '):
                    print(groups)
                    continue

                if text.startswith('/send '):
                    split_text = text.split(" ", 2)
                    if len(split_text) < 3:
                        print("Uso: /send <dest> <msg>")
                        continue
                    dest = split_text[1]
                    if dest not in public_keys:
                        print("Você não tem a chave pública desse usuário. Use /add <user>")
                        continue
                    plaintext = split_text[2]
                    mensagem = f'{nickname}: {plaintext}'
                    cipherText, aes_key, iv, tag = cripto.AES_encrypt(mensagem)
                    aes_key_encrypted = cripto.RSA_encrypt(aes_key, public_keys[dest])

                    payload = {
                        'cmd':'/send',
                        'sender': nickname,
                        'dest':dest,
                        'aes_key_encrypted': base64.b64encode(aes_key_encrypted).decode(encoding),
                        'iv': base64.b64encode(iv).decode(encoding),
                        'tag': base64.b64encode(tag).decode(encoding),
                        'ciphertext': base64.b64encode(cipherText).decode(encoding)
                    }
                    
                    to_sign = json.dumps(payload, sort_keys=True).encode(encoding)
                    signature = cripto.RSA_sign(to_sign, private_key)

                    if DEBUG:
                        print(f"\n[DEBUG] tag: {tag}")
                        print(f"\n[DEBUG] Texto cifrado enviado: {cipherText}")
                        print(f"\n[DEBUG] Chave AES: {aes_key}")
                        print(f"\n[DEBUG] Chave AES encriptada: {aes_key_encrypted}")
                        print(f"\n[DEBUG] Assinatura: {signature}\n")

                    payload['signature'] = base64.b64encode(signature).decode(encoding)
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    continue

                if text.startswith('/creategroup'):
                    split_text = text.split(" ", 2)
                    if len(split_text) < 3:
                        print("Uso: /creategroup <group> <member1,member2,...>")
                        continue
                    group = split_text[1]
                    members_raw = split_text[2]
                    members = [m.strip() for m in members_raw.split(',') if m.strip()]
                    if nickname not in members:
                        members.append(nickname)

                    missing = [m for m in members if m not in public_keys]
                    if missing:
                        print(f"Não estão adicionados: {missing}.")
                        continue

                    aes_key = cripto.AES_key_generate()
                    enc_keys = {}
                    for m in members:
                        enc = cripto.RSA_encrypt(aes_key, public_keys[m])
                        enc_keys[m] = base64.b64encode(enc).decode(encoding)

                    group_keys[group] = aes_key
                    groups[group] = members
                    count_msg_groups[group] = 0

                    payload = {
                        'cmd':'/creategroup',
                        'group':group,
                        'creator':nickname,
                        'members':members,
                        'enc_keys':enc_keys}

                    if DEBUG:
                        print(f"\n[DEBUG] Chave de grupo enviada: {aes_key}")
                        print(f"\n[DEBUG] Chave de grupo encriptada: {enc_keys}\n")

                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    print(f"[CLIENT] Grupo '{group}' criado com membros: {members}")
                    continue

                if text.startswith('/gsend '):
                    split_text = text.split(" ", 2)
                    if len(split_text) < 3:
                        print("Uso: /gsend <group> <msg>")
                        continue

                    group = split_text[1]
                    msg = split_text[2]
                    aes_key = group_keys.get(group)

                    if not aes_key:
                        print("Você não tem a chave do grupo. Peça ao owner.")
                        continue

                    mensagem = f"{nickname} [grupo:{group}]: {msg}"
                    cipherText, _, iv, tag = cripto.AES_encrypt(mensagem, key_override=aes_key)

                    payload = {
                        'cmd':'/gsend',
                        'sender':nickname,
                        'group':group,
                        'iv': base64.b64encode(iv).decode(encoding),
                        'tag': base64.b64encode(tag).decode(encoding),
                        'ciphertext': base64.b64encode(cipherText).decode(encoding)                        
                        }
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    continue

                if text.startswith('/addmember '):
                    split_text = text.split(' ', 2)
                    if len(split_text) != 3:
                        print("Uso: /addmember <group> <user>")
                        continue
                    group = split_text[1]; new_user = split_text[2].strip()
                    if group not in groups:
                        print("Grupo desconhecido localmente.")
                        continue

                    new_members = list(groups[group])
                    if new_user not in new_members:
                        new_members.append(new_user)

                    missing = [m for m in new_members if m not in public_keys]
                    if missing:
                        print(f"Não estão adicionados:: {missing}")
                        continue

                    new_aes = cripto.AES_key_generate()
                    enc_keys = {}
                    for m in new_members:
                        enc = cripto.RSA_encrypt(new_aes, public_keys[m])
                        enc_keys[m] = base64.b64encode(enc).decode(encoding)

                    group_keys[group] = new_aes
                    groups[group] = new_members

                    payload = {
                        'cmd':'/addmember',
                        'group':group,
                        'actor':nickname,
                        'new_member':new_user,
                        'enc_keys':enc_keys}
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    print(f"[CLIENT] Pedido de adicionar {new_user} a {group} enviado.")
                    continue

                if text.startswith('/removemember '):
                    split_text = text.split(' ', 2)
                    if len(split_text) != 3:
                        print("Uso: /removemember <group> <user>")
                        continue

                    group = split_text[1]; rem_user = split_text[2].strip()
                    if group not in groups:
                        print("Grupo desconhecido localmente.")
                        continue

                    new_members = [m for m in groups[group] if m != rem_user]
                    missing = [m for m in new_members if m not in public_keys]
                    if missing:
                        print(f"Não estão adicionados: {missing}")
                        continue

                    new_aes = cripto.AES_key_generate()
                    enc_keys = {}
                    for m in new_members:
                        enc = cripto.RSA_encrypt(new_aes, public_keys[m])
                        enc_keys[m] = base64.b64encode(enc).decode(encoding)

                    group_keys[group] = new_aes
                    groups[group] = new_members
                    payload = {
                        'cmd':'/removemember',
                        'group':group,
                        'actor':nickname,
                        'remove':rem_user,
                        'enc_keys':enc_keys}
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    print(f"[CLIENT] Pedido de remover {rem_user} de {group} enviado.")
                    continue

                if text.startswith('/leavegroup '):
                    split_text = text.split(' ', 1)
                    if len(split_text) != 2:
                        print("Uso: /leavegroup <group>")
                        continue

                    group = split_text[1].strip()
                    payload = {
                        'cmd':'/leavegroup',
                        'group':group,
                        'member':nickname}
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)

                    # local cleanup
                    if group in groups:
                        groups[group] = [m for m in groups[group] if m != nickname]
                    if group in group_keys:
                        del group_keys[group]
                    print(f"[CLIENT] Você saiu do grupo {group}")
                    continue

                if text.startswith('/rotategroup '):
                    split_text = text.split(' ', 1)
                    if len(split_text) != 2:
                        print("Uso: /rotategroup <group>")
                        continue

                    group = split_text[1].strip()
                    if group not in groups:
                        print("Grupo desconhecido localmente.")
                        continue

                    members = groups[group]
                    missing = [m for m in members if m not in public_keys]
                    if missing:
                        print(f"Não estão adicionados: {missing}")
                        continue

                    new_aes = cripto.AES_key_generate()
                    enc_keys = {}
                    for m in members:
                        enc = cripto.RSA_encrypt(new_aes, public_keys[m])
                        enc_keys[m] = base64.b64encode(enc).decode(encoding)
                    
                    if DEBUG:
                        print(f"\n[DEBUG] Troca de chave de grupo:")
                        print(f"[DEBUG] Antiga chave: {group_keys[group]}")
                        print(f"[DEBUG] Nova chave: {aes_key}")
                        print(f"[DEBUG] Nova chave encriptada: {enc_keys}\n")
                    
                    group_keys[group] = new_aes
                    payload = {
                        'cmd':'/rotategroup',
                        'group':group,
                        'actor':nickname,
                        'enc_keys':enc_keys}
                    
                    pld = json.dumps(payload).encode(encoding)
                    client.send(len(pld).to_bytes(4)); client.send(pld)
                    print(f"[CLIENT] Pedido de rotação de chave para {group} enviado.")
                    continue

        except Exception as e:
            print(f"[CLIENT] Falha ao enviar a mensagem: {e}")
            return

thread_receber = threading.Thread(target=receber)
thread_receber.start()

thread_escrever = threading.Thread(target=escrever)
thread_escrever.start()
