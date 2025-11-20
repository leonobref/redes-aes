# Cliente_k_v5.py
import socket
import threading
import json
import base64
import cripto
import getpass
import hashlib
import binascii
import hmac
import os

encoding = 'utf-8'
DEBUG = False
LOGIN = False

print("Digite 1 para Registrar")
print("Digite 2 para Logar")

opcao = input("Escolha uma opção (1=Registrar, 2=Logar): ").strip()
if opcao not in ('1', '2'):
    print("Opção inválida. Saindo.")
    raise SystemExit

action = 'register' if opcao == '1' else 'login'
nickname = input("Escolha um nickname: ").strip()
password = getpass.getpass("Senha: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 55555))

private_key, public_key = cripto.RSA_keys_generate()

# server public key (será recebido do servidor logo após challenge)
server_public_key_pem = None

public_keys = {}
group_keys = {}
groups = {}

PBKDF2_ITERS = 200000

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_json(sock, obj):
    b = json.dumps(obj).encode(encoding)
    sock.send(len(b).to_bytes(4)); sock.send(b)

def receber():
    global LOGIN, server_public_key_pem
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
                    if DEBUG:
                        print(f"[CLIENT] Pedido de rotação de chave para {group} enviado.")
                    continue

                elif cmd == 'become_owner':
                    grp = payload.get('group')
                    print(f"[CLIENT] Você agora é dono do grupo {grp}.")

                elif cmd == 'removed':
                    print(f"[CLIENT] {payload.get('msg')}")

                elif cmd == 'error':
                    print(f"[CLIENT] ERRO: {payload.get('msg')}")

                elif cmd == '/update_pubkey':
                    user = payload.get('user')
                    key_b64 = payload.get('key')
                    if user in public_keys:
                        new_key = base64.b64decode(key_b64)
                        public_keys[user] = new_key
                        print(f"[CLIENT] Nova chave pública de {user} atualizada automaticamente.")
                    else:
                        if DEBUG:
                            print(f"[DEBUG] Recebida atualização de pubkey de {user}, mas não estava em public_keys local.")

                else:
                    print(f"[CLIENT] Payload desconhecido: {payload}")

            else:
                # fase antes do login: receber challenge (já foi enviado pelo servidor)
                tam_challenge = int.from_bytes(recvall(client, 4))
                challenge = recvall(client, tam_challenge)

                # RECEBE TAMBÉM a chave pública do servidor (após challenge)
                tam_srv_pub = int.from_bytes(recvall(client, 4))
                server_public_key_pem = recvall(client, tam_srv_pub)

                # assina challenge com RSA privada como antes
                signature = cripto.RSA_sign(challenge, private_key)

                if DEBUG:
                    print(f"\n[DEBUG] Assinatura: {signature}\n")

                # envia chave pública do cliente
                client.send(len(public_key).to_bytes(4)); client.send(public_key)

                # envia assinatura
                client.send(len(signature).to_bytes(4)); client.send(signature)

                # envia nickname
                encode_nick = nickname.encode(encoding)
                client.send(len(encode_nick).to_bytes(4)); client.send(encode_nick)

                # envia apenas a ação (register/login) — **não envia a senha aqui**
                cred = {'action': action}
                client.send(len(json.dumps(cred).encode(encoding)).to_bytes(4))
                client.send(json.dumps(cred).encode(encoding))

                # agora aguardamos instruções do servidor:
                # - se register -> servidor pedirá registro (antes request_password)
                # - se login -> servidor enviará salt em payload cmd 'auth_challenge'
                tam_srv = int.from_bytes(recvall(client, 4))
                resp = json.loads(recvall(client, tam_srv).decode(encoding))

                # registro: servidor pede dados de registro (não envia senha em texto)
                if resp.get('cmd') == 'request_password':
                    # CLIENTE: gera salt localmente, derive dk = PBKDF2(password, salt),
                    # cifre dk com a chave pública do servidor e envie salt + dk_enc (base64)
                    salt = os.urandom(16)
                    salt_hex = binascii.hexlify(salt).decode('ascii')
                    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS)
                    # cifra dk com a chave pública do servidor
                    enc = cripto.RSA_encrypt(dk, server_public_key_pem)
                    dk_enc_b64 = base64.b64encode(enc).decode(encoding)

                    to_send = {'salt': salt_hex, 'dk_enc': dk_enc_b64}
                    send_json(client, to_send)

                    # agora servidor responderá com 'NICK' ou erro via mensagem simples
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
                        if mensagem.startswith('{'):
                            resp = json.loads(mensagem)
                            if resp.get('cmd') == 'auth_failed':
                                print(resp.get('msg'))
                                continue
                        else:
                            print(mensagem)
                        continue

                # login: servidor retornou salt -> calculo prova e envio
                elif resp.get('cmd') == 'auth_challenge':
                    salt_hex = resp.get('salt')
                    salt = binascii.unhexlify(salt_hex.encode('ascii'))
                    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS)
                    proof = hmac.new(dk, challenge, hashlib.sha256).hexdigest()
                    send_json(client, {'proof': proof})

                    # aguarda resposta simples do servidor
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
                        print("/rotategroup <group)\n")
                    else:
                        print(mensagem)
                        client.close()
                        break

                else:
                    # resposta inesperada
                    print(f"[CLIENT] Resposta inesperada do servidor: {resp}")
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

                # resto das operações de grupo e comandos permanece igual...
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

                # outras funções (addmember, removemember, etc.) permanecem as mesmas

        except Exception as e:
            print(f"[CLIENT] Falha ao receber a mensagem: {e}")
            client.close()
            break

thread_receber = threading.Thread(target=receber)
thread_receber.start()

thread_escrever = threading.Thread(target=escrever)
thread_escrever.start()
