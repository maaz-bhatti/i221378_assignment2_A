#!/usr/bin/env python3
import os
import socket
import json
import base64
import time
from getpass import getpass
from securechat import crypto_utils as cu
from cryptography.hazmat.primitives.serialization import load_pem_private_key

HOST = os.environ.get('SERVER_HOST','127.0.0.1')
PORT = int(os.environ.get('SERVER_PORT','9000'))
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

CLIENT_KEY = os.environ.get('CLIENT_KEY', os.path.join(CERTS_DIR, 'client.alice.key.pem'))
CLIENT_CERT = os.environ.get('CLIENT_CERT', os.path.join(CERTS_DIR, 'client.alice.cert.pem'))
CA_CERT = os.path.join(CERTS_DIR, 'ca.cert.pem')

def send_json(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_json(sock):
    hdr = sock.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("Connection closed")
    l = int.from_bytes(hdr, 'big')
    data = b''
    while len(data) < l:
        chunk = sock.recv(l - len(data))
        if not chunk:
            raise ConnectionError("Connection closed mid-read")
        data += chunk
    return json.loads(data.decode('utf-8'))

def verify_server_cert(cert_pem):
    ca = cu.load_certificate(CA_CERT)
    cert = cu.load_certificate(cert_pem.encode('utf-8') if isinstance(cert_pem, bytes) else cert_pem)
    # simple validation: issuer == ca.subject, not expired, signature ok
    if cert.issuer != ca.subject:
        return False, "BAD ISSUER"
    now = datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        return False, "EXPIRED"
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    except Exception as e:
        return False, "SIGNATURE FAIL"
    return True, "OK"

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    # send hello
    with open(CLIENT_CERT,'r') as f:
        cert_pem = f.read()
    nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
    send_json(s, {"type":"hello","client cert": cert_pem, "nonce": nonce})
    # receive server hello
    sh = recv_json(s)
    server_cert = sh.get('server cert')
    ok, reason = True, "OK"  # ideally validate against CA
    # Now do ephemeral DH for temporary AES
    g = cu.DEFAULT_G; p = cu.DEFAULT_P
    a = cu.dh_generate_private_key(256)
    A = cu.dh_public(g,p,a)
    send_json(s, {"type":"dh client","g": str(g), "p": str(p), "A": str(A)})
    dh_server = recv_json(s)
    B = int(dh_server['B'])
    Ks = cu.dh_shared(B, a, p)
    temp_key = cu.trunc16_sha256_of_int(Ks)
    # register/login
    action = input("Type 'r' to register or 'l' to login: ").strip().lower()
    email = input("email: ").strip()
    username = input("username: ").strip()
    pwd = getpass("password: ")
    payload = {"email": email, "username": username, "pwd": pwd}
    enc = cu.aes_encrypt(temp_key, json.dumps(payload).encode('utf-8'))
    send_json(s, {"type": "register" if action=='r' else "login", "payload": base64.b64encode(enc).decode('utf-8')})
    resp = recv_json(s)
    if resp.get('type')=='register result' and not resp.get('ok'):
        print("Register failed")
        s.close(); return
    if resp.get('type')=='login result' and not resp.get('ok'):
        print("Login failed")
        s.close(); return
    print("Authenticated. Proceeding to session DH.")
    # session DH
    a2 = cu.dh_generate_private_key(256)
    A2 = cu.dh_public(g,p,a2)
    send_json(s, {"type":"dh client","g":str(g),"p":str(p),"A":str(A2)})
    srv = recv_json(s)
    B2 = int(srv['B'])
    Ks2 = cu.dh_shared(B2, a2, p)
    session_key = cu.trunc16_sha256_of_int(Ks2)
    # load client private key for signing
    client_priv = load_pem_private_key(open(CLIENT_KEY,'rb').read(), password=None)

    # interactive send loop
    seqno = 0
    while True:
        text = input("msg> ")
        if text.strip().lower() == '/quit':
            send_json(s, {"type":"close"})
            break
        if text.strip().lower() == '/receipt':
            send_json(s, {"type":"receipt_request"})
            receipt = recv_json(s)
            print("Receipt:", receipt)
            continue
        seqno += 1
        ts = int(time.time()*1000)
        ct = cu.aes_encrypt(session_key, text.encode('utf-8'))
        # compute digest
        import hashlib
        h = hashlib.sha256()
        h.update(str(seqno).encode('utf-8'))
        h.update(str(ts).encode('utf-8'))
        h.update(ct)
        digest = h.digest()
        sig = client_priv.sign(digest, cu.padding.PKCS1v15(), cu.hashes.SHA256())
        send_json(s, {"type":"msg","seqno": seqno, "ts": ts,
                      "ct": base64.b64encode(ct).decode('utf-8'),
                      "sig": base64.b64encode(sig).decode('utf-8')})
    s.close()

if __name__ == '__main__':
    main()
