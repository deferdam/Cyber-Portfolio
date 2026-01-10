# Secure File Vault

Secure File Vault is a local application designed to protect sensitive files by encrypting and decrypting them using a password provided by the user.

The primary objective is to ensure that file content remains confidential even if the encrypted file is stolen or accessed by an unauthorized person.

---

## Project Overview

The system works in a simple and secure way:

1. The user selects a file.
2. The user chooses whether to encrypt or decrypt it.
3. A password is entered.
4. The password is transformed into a cryptographic key using a secure key derivation function.
5. The file is encrypted or decrypted using this derived key.

Important principles:
- No encryption key is stored permanently.
- The only secret is the user's password.
- If the password is lost, the data cannot be recovered.

---

## Main Components

- CLI Interface  
  Handles user interaction and file selection.

- Key Management Module  
  Responsible for password validation and key derivation.

- Cryptographic Core  
  Performs encryption and decryption using secure algorithms.

- Testing & Documentation  
  Ensures reliability, clarity, and maintainability of the project.

---

## Technical Direction

The project follows these principles:
- Strong separation of concerns between modules.
- Secure cryptographic practices.
- Clear documentation and maintainable code.

---

## Technologies Used

- Python
- Cryptography library
- MkDocs for documentation
- Command Line Interface (CLI)

---

## How to View the Documentation

Refer to the file:
`DOCS_HOW_TO_RUN.md`

It explains step-by-step how to run and stop the documentation website locally.

---

End of README.
