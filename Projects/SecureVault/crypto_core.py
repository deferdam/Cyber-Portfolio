from cryptography.fernet import Fernet

def get_fernet(key: bytes) -> Fernet:

    return Fernet(key)

def encrypt_file(path: str, key: bytes) -> str:
    fernet = get_fernet(key)

    with open(path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    new_path = path + ".enc"

    with open(new_path, "wb") as f:
        f.write(encrypted)

    return new_path


def decrypt_file(path: str, key: bytes) -> str:
    fernet = get_fernet(key)

    with open(path, "rb") as f:
        data = f.read()

    decrypted = fernet.decrypt(data)

    if path.endswith(".enc"):
        new_path = path[:-4]
    else:
        new_path = path + ".dec"

    with open(new_path, "wb") as f:
        f.write(decrypted)

    return new_path
