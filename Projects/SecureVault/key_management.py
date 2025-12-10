import os
import re
import base64
from hashlib import pbkdf2_hmac


# ============================================================
# 1. SALT GENERATION
# ============================================================

def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    Default size: 16 bytes (128 bits).
    """
    return os.urandom(length)


# ============================================================
# 2. KEY DERIVATION WITH PBKDF2-HMAC-SHA256 (FERNET-COMPATIBLE)
# ============================================================

def derive_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Derive a 256-bit key from a user password using PBKDF2.

    Returns a Fernet-compatible key:
    - PBKDF2-HMAC-SHA256
    - 390k iterations
    - raw key = 32 bytes
    - encoded as URL-safe base64 (what cryptography.Fernet expects)
    """
    raw_key = pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    # Fernet requires a URL-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(raw_key)


# ============================================================
# 3. SALT STORAGE / LOADING
# ============================================================

def save_salt(path: str, salt: bytes):
    """
    Save the salt into a binary file.
    """
    with open(path, "wb") as f:
        f.write(salt)


def load_salt(path: str) -> bytes:
    """
    Load an existing salt from a binary file.
    """
    with open(path, "rb") as f:
        return f.read()


# ============================================================
# 4. PASSWORD POLICY
# ============================================================

def check_password_strength(password: str) -> bool:
    """
    Check whether the password satisfies the minimum policy:
    - at least 10 characters
    - at least one uppercase letter
    - at least one lowercase letter
    - at least one digit
    - at least one special character
    """
    if len(password) < 10:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[\W_]", password):
        return False
    return True


# ============================================================
# 5. KEY PREPARATION (HIGH-LEVEL API)
# ============================================================

def prepare_key(password: str, salt_path: str) -> bytes:
    """
    High-level function to prepare a key for encryption/decryption.
    It performs:
    - Password strength validation
    - Salt loading (if decrypting)
    - Salt generation (if encrypting)
    - Key derivation using PBKDF2 (Fernet-compatible)
    """
    # Validate password
    if not check_password_strength(password):
        raise ValueError(
            "Weak password. Must contain at least 10 characters, "
            "uppercase, lowercase, digits and special symbols."
        )

    # Load salt if it already exists (decryption)
    if os.path.exists(salt_path):
        salt = load_salt(salt_path)
    else:
        # Create new salt for encryption
        salt = generate_salt()
        save_salt(salt_path, salt)

    # Derive final (Fernet-compatible) key
    key = derive_key(password, salt)
    return key
