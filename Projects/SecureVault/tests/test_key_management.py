import os
from key_management import (
    generate_salt,
    derive_key,
    save_salt,
    load_salt,
    check_password_strength,
    prepare_key,
)


# ============================================================
# 1. TEST SALT GENERATION
# ============================================================

def test_generate_salt():
    salt1 = generate_salt()
    salt2 = generate_salt()

    # Salt must have the correct size
    assert len(salt1) == 16
    assert len(salt2) == 16

    # Salts must be random
    assert salt1 != salt2


# ============================================================
# 2. TEST KEY DERIVATION
# ============================================================

def test_key_derivation_same_inputs():
    password = "StrongPassword123!"
    salt = b"aaaaaaaaaaaaaaaa"  # 16 bytes

    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)

    # Same password + same salt = same key
    assert key1 == key2


def test_key_derivation_different_salts():
    password = "StrongPassword123!"
    salt1 = b"1111111111111111"
    salt2 = b"2222222222222222"

    key1 = derive_key(password, salt1)
    key2 = derive_key(password, salt2)

    # Same password + different salts = different keys
    assert key1 != key2


# ============================================================
# 3. TEST SALT SAVE / LOAD
# ============================================================

def test_salt_save_and_load():
    salt = generate_salt()
    path = "test_salt.bin"

    save_salt(path, salt)
    loaded_salt = load_salt(path)

    assert salt == loaded_salt

    os.remove(path)


# ============================================================
# 4. TEST PASSWORD POLICY
# ============================================================

def test_password_policy():
    assert check_password_strength("AstrongPass1!") is True
    assert check_password_strength("weak") is False
    assert check_password_strength("NoSpecialChar1") is False
    assert check_password_strength("NOSMALL1!") is False
    assert check_password_strength("nouppercase1!") is False


# ============================================================
# 5. TEST PREPARE_KEY
# ============================================================

def test_prepare_key_creation_and_reuse():
    password = "VeryStrongPass1!"
    salt_path = "test_salt2.bin"

    # First call → creates new salt
    key1 = prepare_key(password, salt_path)
    assert os.path.exists(salt_path)

    # Second call → uses the same salt, so the key must match
    key2 = prepare_key(password, salt_path)
    assert key1 == key2

    os.remove(salt_path)


if __name__ == "__main__":
    print("Running tests...")

    test_generate_salt()
    test_key_derivation_same_inputs()
    test_key_derivation_different_salts()
    test_salt_save_and_load()
    test_password_policy()
    test_prepare_key_creation_and_reuse()

    print("All tests passed successfully!")
