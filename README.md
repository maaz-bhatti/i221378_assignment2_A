# SecureChat (Assignment 2) — Implementation

## Overview
This repository implements the Secure Chat assignment:
- Application-layer PKI (self CA)
- Mutual X.509 cert exchange
- Registration/Login protected by ephemeral DH → AES
- Session key via DH → AES-128
- Per-message SHA-256 + RSA signature
- Append-only transcript + SessionReceipt
- MySQL storage for users (salted SHA-256)

## Setup

1. Create a Python virtualenv and install requirements:

2. Create certs:
This writes to `certs/`.

3. Setup MySQL:
- Ensure MySQL server running
- Create DB and table:

4. Run server:

5. Run client (in another terminal):
