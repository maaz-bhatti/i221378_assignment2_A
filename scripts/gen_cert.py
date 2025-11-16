#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')
os.makedirs(CERTS_DIR, exist_ok=True)

def load_ca():
    with open(os.path.join(CERTS_DIR, 'ca.key.pem'), 'rb') as f:
        key_data = f.read()
    with open(os.path.join(CERTS_DIR, 'ca.cert.pem'), 'rb') as f:
        cert_data = f.read()
    ca_key = load_pem_private_key(key_data, password=None)
    ca_cert = x509.load_pem_x509_certificate(cert_data)
    return ca_key, ca_cert

def gen_cert(common_name, kind):
    ca_key, ca_cert = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    keyfile = os.path.join(CERTS_DIR, f'{kind}.{common_name}.key.pem')
    certfile = os.path.join(CERTS_DIR, f'{kind}.{common_name}.cert.pem')
    with open(keyfile, 'wb') as f:
        f.write(key_pem)
    with open(certfile, 'wb') as f:
        f.write(cert_pem)
    print("Wrote:", keyfile, certfile)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python gen_cert.py <kind:server|client> <common_name>")
        sys.exit(1)
    kind = sys.argv[1]
    cn = sys.argv[2]
    gen_cert(cn, kind)
