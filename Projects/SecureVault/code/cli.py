from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Literal

import tkinter as tk
from tkinter import filedialog

from tests.key_management import derive_key
from crypto_core import encrypt_file, decrypt_file


Action = Literal["encrypt", "decrypt"]


def ask_action() -> Action:
    """
    Ask the user whether they want to encrypt or decrypt.
    Loops until a valid answer is provided.
    """
    while True:
        answer = input("Do you want to encrypt (e) or decrypt (d)? ").strip().lower()

        if answer in ("e", "encrypt"):
            return "encrypt"
        if answer in ("d", "decrypt"):
            return "decrypt"

        print("Invalid choice. Please type 'e' for encrypt or 'd' for decrypt.")


def select_files_via_dialog() -> list[str]:
    """
    Open a file explorer dialog and let the user choose one or more files.
    Returns a list of selected paths as strings (empty list if nothing was chosen).
    """
    root = tk.Tk()
    root.withdraw()
    file_paths = filedialog.askopenfilenames()
    root.destroy()

    # askopenfilenames returns a tuple; convert to list of strings
    return list(file_paths)


def ask_file_paths() -> list[str]:
    """
    Ask the user how they want to select the files:
    - manually typing the paths (one by one)
    - using the file explorer dialog

    Returns:
        List of file paths as strings.
    """
    while True:
        print("\nHow do you want to select the file(s)?")
        print("  1) Type the path(s) manually")
        print("  2) Use the file explorer (multiple selection allowed)")
        choice = input("Choice (1/2): ").strip()

        if choice == "1":
            paths: list[str] = []
            print("\nManual mode. Enter one file path per line.")
            print("Press ENTER on an empty line when you are done.\n")
            while True:
                path = input("File path (or empty to finish): ").strip()
                if not path:
                    break
                paths.append(path)

            if paths:
                return paths

            print("No path provided. Please try again.")

        elif choice == "2":
            paths = select_files_via_dialog()
            if paths:
                return paths
            print("No file selected. Please try again.")
        else:
            print("Invalid choice. Please type 1 or 2.")


def main() -> None:
    """
    Main entry point.
    For now:
    - choose action
    - choose one or more files
    - normalize paths
    - print and exit
    """
    print("=== Secure File Vault ===")

    action: Action = ask_action()
    raw_paths: list[str] = ask_file_paths()

    normalized_paths: list[str] = [
        str(Path(p).expanduser().resolve()) for p in raw_paths
    ]

    files_chain: str = ";".join(normalized_paths)

    print("\nSummary:")
    print(f"  Action      : {action}")
    print("  Files list  :")
    for p in normalized_paths:
        print(f'    - "{p}"')
    print(f'\n  Files chain : "{files_chain}"')

    password = input("\nEnter password: ").strip()

    print("\nProcessing...\n")

    for path in normalized_paths:
        try:
            if action == "encrypt":
                salt = os.urandom(16)

                key = derive_key(password, salt)

                out_file = encrypt_file(path, key)

                with open(out_file, "rb") as f:
                    encrypted_data = f.read()

                with open(out_file, "wb") as f:
                    f.write(salt + encrypted_data)

                print(f"Encrypted: {out_file}")

            else:  # decrypt
                with open(path, "rb") as f:
                    salt = f.read(16)
                    encrypted_data = f.read()

                key = derive_key(password, salt)

                temp_path = path + ".tmp"
                with open(temp_path, "wb") as f:
                    f.write(encrypted_data)

                try:
                    out_file = decrypt_file(temp_path, key)

                except Exception:
                    os.remove(temp_path)
                    print(f"Wrong password or corrupted file: {path}")
                    continue

                os.remove(temp_path)

                if out_file.endswith(".dec"):
                    restored = out_file[:-12]
                    os.rename(out_file, restored)
                    out_file = restored

                print(f"Decrypted: {out_file}")

        except Exception as err:
            print(f"Error processing {path}: {err}")

    print("\nDone.")
    sys.exit(0)


if __name__ == "__main__":
    main()
