#!/usr/bin/env python3
import os
import socket
import json
import base64
import time
from datetime import datetime
from securechat import crypto_utils as cu
from securechat.db import DB
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

HOST = '0.0.0.0'
PORT = 9000
CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

SERVER_KEY = os.environ.get('SERVER_KEY', os.path.join(CERTS_DIR, 'server.server.key.pem')) # update name
SERVER_CERT = os.environ.get('SERVER_CERT', os.path.join(CERTS_DIR, 'server.server.cert.pem'))
CA_CERT = os.path.join(CERTS_DIR, 'ca.cert.pem')

TRANSCRIPT_DIR = os.path.join(os.path.dirname(__file__), '..', 'transcripts')
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)

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

def verify_certificate(cert_pem_bytes):
    ca = x509.load_pem_x509_certificate(open(CA_CERT,'rb').read())
    cert = x509.load_pem_x509_certificate(cert_pem_bytes.encode('utf-8'))
    # verify issuer matches CA subject
    if cert.issuer != ca.subject:
        return False, "BAD ISSUER"
    # expiry
    now = datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        return False, "EXPIRED"
    # simple signature check using CA public key
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm
        )
    except Exception as e:
        return False, "SIGNATURE FAIL: " + str(e)
    return True, "OK"

def handle_client_conn(conn, addr):
    print("Connection from", addr)
    db = DB()
    transcript = []
    seqno_counter = 0

    # 1) receive "hello" with client cert and nonce
    hello = recv_json(conn)
    client_cert_pem = hello.get('client cert')
    ok, reason = verify_certificate(client_cert_pem)
    if not ok:
        send_json(conn, {"type":"error","msg":"BAD CERT: "+reason})
        conn.close()
        return
    # send server hello
    server_cert_pem = open(SERVER_CERT, 'r').read()
    nonce_server = base64.b64encode(os.urandom(16)).decode('utf-8')
    send_json(conn, {"type":"server hello","server cert":server_cert_pem,"nonce":nonce_server})
    # expect to receive temp-dh params encrypted under ephemeral AES? The spec uses temporary DH then AES temporary key for register/login
    # For simplicity: Perform ephemeral DH here to derive a temporary AES key for registration/login
    # DH handshake:
    dh_client = recv_json(conn)
    if dh_client.get('type') != 'dh client':
        send_json(conn, {"type":"error","msg":"expected dh client"})
        conn.close(); return
    g = int(dh_client['g'])
    p = int(dh_client['p'])
    A = int(dh_client['A'])
    priv = cu.dh_generate_private_key(256)
    B = cu.dh_public(g, p, priv)
    send_json(conn, {"type":"dh server","B": str(B)})
    Ks = cu.dh_shared(A, priv, p)
    temp_key = cu.trunc16_sha256_of_int(Ks)

    # Next receive encrypted register/login payload
    payload_msg = recv_json(conn)
    if payload_msg.get('type') not in ('register', 'login'):
        send_json(conn, {"type":"error","msg":"expected register/login"})
        conn.close(); return
    enc_b64 = payload_msg.get('payload')
    enc = base64.b64decode(enc_b64)
    try:
        plaintext = cu.aes_decrypt(temp_key, enc)
        obj = json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        send_json(conn, {"type":"error","msg":"decrypt failed"})
        conn.close(); return

    if payload_msg['type']=='register':
        # expected email, username, pwd (plain, we hash server side)
        email = obj['email']
        username = obj['username']
        pwd = obj['pwd']
        ok = db.create_user(email, username, pwd)
        send_json(conn, {"type":"register result","ok": ok})
        if not ok:
            conn.close(); return
    else: # login
        email = obj['email']
        pwd = obj['pwd']
        if not db.verify_user(email, pwd):
            send_json(conn, {"type":"login result","ok": False})
            conn.close(); return
        send_json(conn, {"type":"login result","ok": True})
    # At this point authentication succeeded and we can proceed to full session DH
    # Perform session DH
    dh2_client = recv_json(conn)
    if dh2_client.get('type')!='dh client':
        send_json(conn, {"type":"error","msg":"expected dh client 2"})
        conn.close(); return
    g2 = int(dh2_client['g']); p2 = int(dh2_client['p']); A2 = int(dh2_client['A'])
    priv2 = cu.dh_generate_private_key(256)
    B2 = cu.dh_public(g2, p2, priv2)
    send_json(conn, {"type":"dh server","B": str(B2)})
    Ks2 = cu.dh_shared(A2, priv2, p2)
    session_key = cu.trunc16_sha256_of_int(Ks2)

    # load server private key for signing
    server_priv = load_pem_private_key(open(os.environ.get('SERVER_KEY', SERVER_KEY),'rb').read(), password=None)
    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
    client_pub = client_cert.public_key()

    # Now handle message loop
    transcript_lines = []
    last_seq = 0
    while True:
        try:
            msg = recv_json(conn)
        except ConnectionError:
            break
        if msg.get('type') == 'msg':
            seqno = int(msg['seqno'])
            ts = int(msg['ts'])
            ct_b64 = msg['ct']
            sig_b64 = msg['sig']
            # verify seqno
            if seqno <= last_seq:
                send_json(conn, {"type":"error","msg":"REPLAY"})
                continue
            last_seq = seqno
            ct = base64.b64decode(ct_b64)
            sig = base64.b64decode(sig_b64)
            # compute hash = sha256(seqno||ts||ct)
            h = hashlib.sha256()
            h.update(str(seqno).encode('utf-8'))
            h.update(str(ts).encode('utf-8'))
            h.update(ct)
            digest = h.digest()
            # verify signature with client's public key
            from cryptography.hazmat.primitives.asymmetric import padding as _pad
            try:
                client_pub.verify(sig, digest, _pad.PKCS1v15(), cu.hashes.SHA256())
            except Exception:
                send_json(conn, {"type":"error","msg":"SIG FAIL"})
                continue
            # decrypt and display
            try:
                pt = cu.aes_decrypt(session_key, ct)
                print(f"[{seqno}] CLIENT: {pt.decode('utf-8')}")
            except Exception:
                send_json(conn, {"type":"error","msg":"DECRYPT FAIL"})
                continue
            # append transcript line
            transcript_lines.append({"seq":seqno,"ts":ts,"ct":ct_b64,"sig":sig_b64,"peer":cu.cert_fingerprint(client_cert)})
            # send ack or reply (server can read from console and send replies)
        elif msg.get('type')=='receipt_request':
            # produce receipt sign(transcript)
            import hashlib as _hash
            concatenated = b''.join([
                (str(line['seq']) + '|' + str(line['ts']) + '|' + line['ct'] + '|' + line['sig'] + '|' + line['peer']).encode('utf-8')
                for line in transcript_lines
            ])
            transcript_hash = _hash.sha256(concatenated).hexdigest()
            sig = server_priv.sign(transcript_hash.encode('utf-8'),
                                   cu.padding.PKCS1v15(), cu.hashes.SHA256())
            send_json(conn, {"type":"receipt", "first_seq": transcript_lines[0]['seq'] if transcript_lines else 0,
                             "last_seq": transcript_lines[-1]['seq'] if transcript_lines else 0,
                             "transcript sha256": transcript_hash, "sig": base64.b64encode(sig).decode('utf-8')})
            # save to file
            fname = os.path.join(TRANSCRIPT_DIR, f"transcript_{int(time.time())}.json")
            with open(fname,'w') as f:
                json.dump(transcript_lines, f, indent=2)
        elif msg.get('type') == 'close':
            break
        else:
            send_json(conn, {"type":"error","msg":"unknown"})
    conn.close()
    db.close()
    print("Connection closed", addr)

def main():
    print("Server starting", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        try:
            handle_client_conn(conn, addr)
        except Exception as e:
            print("Error handling client:", e)
            conn.close()

if __name__ == '__main__':
    main()
