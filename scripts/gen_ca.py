#!/usr/bin/env python3
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')
os.makedirs(CERTS_DIR, exist_ok=True)

def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(CERTS_DIR, 'ca.key.pem'), 'wb') as f:
        f.write(key_pem)
    with open(os.path.join(CERTS_DIR, 'ca.cert.pem'), 'wb') as f:
        f.write(cert_pem)

    print("Wrote CA key and cert to:", CERTS_DIR)

if __name__ == '__main__':
    main()
