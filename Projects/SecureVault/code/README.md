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

## Installation & Setup Instructions

### 1. Install Dependencies

Before running the project, install all required Python packages using the provided `requirements.txt` file:

    pip install -r requirements.txt

This ensures all necessary libraries are available, including cryptographic and interface dependencies.

---

### 2. How to Run the System

Once dependencies are installed, launch the application:

    python cli.py

Follow the CLI instructions to:
- Select a file
- Choose encryption or decryption mode
- Enter a password when prompted

---

### 3. How to Test the System

1. Create and activate a Python virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install project test/runtime dependencies:

```bash
pip install -r requirements.txt
# optionally: pip install coverage
```

3. Run the test suite with verbose output:

```bash
python -m pytest tests -v
```

4. Run an individual test file or test function, for example:

```bash
python -m pytest tests/test_key_management.py::test_password_policy -q
```

Notes:
- Tests may create small temporary files (the tests clean up after themselves where applicable).
- If a test touches the working directory, run tests from the repository root to ensure correct relative paths.
---

### Requirements File

The file `requirements.txt` contains all dependencies required to run the system.  
It must be installed before using the software.

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
@