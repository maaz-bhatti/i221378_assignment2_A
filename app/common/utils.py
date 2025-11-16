import os
import json
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

# PKCS#7 padding
def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len

def pkcs7_unpad(data):
    if not data:
        raise ValueError("Invalid padding (empty)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return iv + ct  # return iv || ct

def aes_decrypt(key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def trunc16_sha256_of_int(n: int) -> bytes:
    # big-endian integer to bytes
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    h = hashlib.sha256(b).digest()
    return h[:16]

# RSA sign/verify using cryptography
def load_private_key(path):
    with open(path, 'rb') as f:
        key = load_pem_private_key(f.read(), password=None)
    return key

def rsa_sign(private_key, data: bytes) -> bytes:
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return sig

def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

# Certificate load/inspect
def load_certificate(path):
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())

def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()

# Simple Diffie-Hellman with group parameters (RFC 7919 would be ideal).
# For assignment simplicity choose a safe 2048-bit prime (use built-in small prime here for clarity).
# In production use well-known group params.
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
DEFAULT_G = 2

def dh_generate_private_key(bits=256):
    # small ephemeral secret (assignment uses ephemeral DH). Use secure random int.
    return int.from_bytes(get_random_bytes(bits//8), 'big')

def dh_public(g, p, private):
    return pow(g, private, p)

def dh_shared(A, private, p):
    return pow(A, private, p)

# JSON helper
def json_encode_bytes(obj):
    # for sending bytes -> base64 if needed. elsewhere handled by caller
    return json.dumps(obj)
