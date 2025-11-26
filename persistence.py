import os
import json
import base64
import cripto


def save_keys_to_file(nickname, private_key_obj, public_key_pem, password, dir_nick, path=None):
    if path is None:
        path = dir_nick + f"/{nickname}_keys.json"
    if not os.path.exists(dir_nick):
        os.mkdir(dir_nick)
    payload = {
        'public_key': public_key_pem.decode('utf-8') if isinstance(public_key_pem, bytes) else public_key_pem,
        'encrypted_private': cripto.encrypt_private_key_with_password(private_key_obj, password)
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=0)
    return path


def load_keys_from_file(nickname, password, dir_nick, path=None):
    if path is None:
        path = dir_nick + f"/{nickname}_keys.json"
    if not os.path.exists(path):
        raise FileNotFoundError("Arquivo de chaves não encontrado. Faça registro primeiro.")
    with open(path, 'r', encoding='utf-8') as f:
        payload = json.load(f)
    public_key = payload['public_key'].encode('utf-8')  # PEM bytes
    private_key_obj = cripto.decrypt_private_key_with_password(payload['encrypted_private'], password)
    return private_key_obj, public_key


def load_saved_pb_keys(nickname, dir_nick):
    filename = dir_nick + f"/pb_keys_{nickname}.json"
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_saved_pb_keys(nickname, groups, dir_nick):
    filename = dir_nick + f"/pb_keys_{nickname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(groups, f, indent=0)


def load_groups_local(nickname, dir_nick):
    filename = dir_nick + f"/groups_{nickname}.json"
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_groups_local(nickname, groups, dir_nick):
    filename = dir_nick + f"/groups_{nickname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(groups, f, indent=0)


def load_groups_key_local(nickname, dir_nick):
    filename = dir_nick + f"/groups_key_{nickname}.json"
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_groups_key_local(nickname, groups, dir_nick):
    filename = dir_nick + f"/groups_key_{nickname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(groups, f, indent=0)