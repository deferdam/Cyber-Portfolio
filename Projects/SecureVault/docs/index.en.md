# Secure File Vault – Overview

Secure File Vault is a local application that lets a user encrypt and decrypt
files using a password. The main goal is to protect the confidentiality of
sensitive files if someone gains access to the computer or backups.

The user:
- chooses whether to encrypt or decrypt,
- selects a file (either manually or through a file explorer),
- enters a strong password.

Internally:
- a key is derived from the password using PBKDF2-HMAC-SHA256 with a random salt,
- the file content is encrypted using a secure algorithm (Fernet) with that key,
- the salt and ciphertext are stored together so the file can be decrypted later.

The application does not keep the key anywhere. The only secret the user must
remember is the password.

This repository currently contains:
- core security module: `key_management.py`
- command-line interface: `cli.py`
- documentation and configuration for a simple documentation site (MkDocs).
