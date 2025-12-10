# Secure File Vault - Architecture Document

## Purpose
This document defines the technical architecture for the Secure File Vault project. It specifies components, responsibilities, data flow, cryptographic decisions, and structural boundaries.

## System Overview
The system is a standalone Python application that encrypts and decrypts files using strong cryptography derived from a user password. It ensures confidentiality even if encrypted files are leaked or stolen, assuming the password is not known.

## Core Components

### CLI Layer (cli.py)
- Handles user input and command parsing
- Prompts password securely
- Forwards requests to internal modules

### Key Management Layer (key_management.py)
- Derives cryptographic keys from passwords
- Generates and stores cryptographic salt
- Enforces password policy

### Cryptographic Core (crypto_core.py)
- Performs encryption and decryption
- Handles only binary keys, never plaintext passwords

## Data Flow
User -> CLI -> Key Management -> Cryptographic Core -> File System

## Encryption Format
[Magic Header: VAULT1]  
[Salt: 16 bytes]  
[Ciphertext: Fernet Format]

## Cryptography
- Encryption: Fernet (AES + HMAC)
- KDF: PBKDF2-HMAC-SHA256
- Iterations: 200000
- Salt Length: 16 bytes
- Key Length: 32 bytes

## Folder Structure
vault/
  code/
    cli.py  
    crypto_core.py  
    key_management.py  
    requirements.txt  
    README.md  
  tests/ 
    key_management.py  
    test_key_management.py  



document/  


## Security Boundaries
- Password handled only in memory
- No sensitive data in logs or disk

## Future Enhancements
- GUI  
- Hardware security integration  
- Multi-user vault  

End of document.
