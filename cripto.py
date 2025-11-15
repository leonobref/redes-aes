# cripto.py
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# ---- RSA helpers ----
def RSA_keys_generate(key_size=2048):
    """
    Retorna: (private_key_obj, public_key_pem_bytes)
    - private_key_obj: objeto RSA (Crypto.PublicKey.RsaKey) para uso interno
    - public_key_pem_bytes: bytes (PEM) que podem ser transmitidos pela rede
    """
    key = RSA.generate(key_size)
    private_key = key         # objeto usado para decodificar
    public_key_pem = key.publickey().export_key(format='PEM')
    return private_key, public_key_pem


def RSA_encrypt(message_bytes, public_key_pem):
    """
    message_bytes: bytes a serem encriptados (p.ex. chave AES)
    public_key_pem: bytes (PEM) recebidos do outro cliente/servidor
    Retorna bytes encriptados.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
    pub = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(pub)
    return cipher_rsa.encrypt(message_bytes)


def RSA_decrypt(ciphertext_bytes, private_key_obj):
    """
    ciphertext_bytes: bytes encriptados com RSA-OAEP
    private_key_obj: objeto retornado por RSA_keys_generate() (RsaKey)
    Retorna bytes descriptografados.
    """
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    return cipher_rsa.decrypt(ciphertext_bytes)


def RSA_sign(challenge, rsa_key_priv):
    '''
    Retorna bytes da assinatura
    '''
    h = SHA256.new(challenge)
    signature = pkcs1_15.new(rsa_key_priv).sign(h)
    return signature


def RSA_verify(msg_bytes, signature_bytes, rsa_key_pub):
    '''
    Retorna ValueError se inválido, retorna True se válido
    '''
    if isinstance(rsa_key_pub, str):
        rsa_key_pub = rsa_key_pub.encode('utf-8')
    
    pub = RSA.import_key(rsa_key_pub)
    h = SHA256.new(msg_bytes)

    try:
        pkcs1_15.new(pub).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False


# ---- AES helpers (AES-256-CBC por simplicidade) ----
def AES_key_generate():
    """Gera chave AES-256 (32 bytes)."""
    return os.urandom(32)


def AES_encrypt(plaintext, key_override=None):
    """
    plaintext: str ou bytes
    key_override: bytes (32) ou None -> se None, gera nova chave
    Retorna: (ciphertext_bytes, aes_key_used_bytes, iv_bytes)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    if key_override is None:
        aes_key = AES_key_generate()
    else:
        aes_key = key_override

    # iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    # ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
    iv = cipher.nonce
    return ciphertext, aes_key, iv, tag


def AES_decrypt(ciphertext, key, iv, tag):
    """
    ciphertext: bytes
    key: bytes (32)
    iv: bytes (16)
    Retorna: plaintext (str)
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    try:
        test = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return False
    plaintext = unpad(test, AES.block_size)
    return plaintext.decode('utf-8')
