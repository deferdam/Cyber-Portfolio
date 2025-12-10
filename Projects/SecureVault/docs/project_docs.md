# Secure File Vault – Project Documentation

This page documents the main components and functions of the Secure File Vault project.

The goal of the project is:
- to encrypt and decrypt files locally,
- using a user-provided password,
- with strong key derivation and clear separation between CLI, key management, and cryptographic core.

---

## 1. High-Level Architecture

Main Python modules:

- `cli.py`  
  Command-line interface. Asks the user:
  - whether they want to encrypt or decrypt,
  - which file they want to process (manual path or file explorer).

- `key_management.py`  
  Security and key logic:
  - password strength validation,
  - salt generation,
  - key derivation using PBKDF2-HMAC-SHA256.

- `crypto_core.py` (future)  
  Will handle:
  - actual encryption,
  - actual decryption,
  - interaction with the derived key and file contents.

You can describe each module in more detail below.

---

## 2. Module: cli.py

### 2.1 Purpose

The `cli.py` module is responsible for interacting with the user.  
It does not perform cryptographic operations. Instead, it:

- asks what action to perform (encrypt or decrypt),
- lets the user select the input file (path or file explorer),
- will later call the key management and crypto core modules.

### 2.2 Functions

#### `ask_action() -> str`

- Asks the user: “encrypt or decrypt?”
- Accepts:
  - `e` or `encrypt` → returns `"encrypt"`
  - `d` or `decrypt` → returns `"decrypt"`
- Loops until a valid response is given.

#### `ask_file_path() -> str`

- Asks the user how they want to select the file:
  - type the path manually,
  - or open a file explorer window.
- Returns the selected path as a string.

#### `select_file_via_dialog() -> str`

- Opens a native file chooser using `tkinter.filedialog`.
- Returns the selected file path as a string, or an empty string if the user cancels.

#### `main()`

- Entry point of the application.
- Calls `ask_action()` and `ask_file_path()`.
- Normalizes the file path (using `pathlib.Path`).
- Prints a summary (for now) and exits.
- In the future, it will:
  - ask for the user password,
  - call `key_management.derive_key(...)`,
  - call encryption or decryption in the crypto core.

---

## 3. Module: key_management.py

### 3.1 Purpose

The `key_management.py` module is responsible for:

- checking password strength,
- generating random salts,
- deriving cryptographic keys from passwords.

It does not interact with files, and it does not perform encryption itself.  
This separation makes it easier to audit and reason about security.

### 3.2 Functions

#### `generate_salt() -> bytes`

- Generates a cryptographically secure random salt using `os.urandom`.
- Returns `SALT_LENGTH` bytes.
- A new salt should be generated for each encryption operation.

#### `verify_password_strength(password: str) -> tuple[bool, str]`

- Applies the password policy:
  - at least 12 characters,
  - include lowercase, uppercase, digit, and special character.
- Returns:
  - a boolean indicating whether the password is strong enough,
  - a message string explaining the decision.

#### `derive_key(password: str, salt: bytes) -> bytes`

- Converts the password (string) into bytes,
- Uses PBKDF2-HMAC-SHA256 with:
  - 200 000 iterations,
  - the given salt,
  - output length of 32 bytes,
- Encodes the raw key using URL-safe Base64 (ready for use with Fernet).
- Returns the derived key as bytes.

---

## 4. How the encryption flow will work (conceptual)

1. The user starts the program (CLI).
2. The CLI asks:
   - action: encrypt or decrypt,
   - file path (manual or explorer).
3. If encrypt:
   - CLI will ask for a password,
   - `key_management` will:
     - validate password strength,
     - generate a salt,
     - derive a key.
   - `crypto_core` will:
     - encrypt the file with the derived key,
     - store salt + ciphertext in the output file.
4. If decrypt:
   - CLI will ask for the password,
   - read the salt from the encrypted file,
   - call `key_management.derive_key(password, salt)`,
   - `crypto_core` will decrypt using the derived key.

---

## 5. Future work

You can extend this document later with:

- details of `crypto_core.py`,
- error handling strategies,
- threat model summary,
- user guides with screenshots or examples.

End of document.
