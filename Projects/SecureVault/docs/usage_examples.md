# Secure File Vault - Usage Examples

## Encrypt a File
python cli.py encrypt --in secret.txt --out secret.vault

Enter password:
************

Output:
File successfully encrypted.

---

## Decrypt a File
python cli.py decrypt --in secret.vault --out secret.txt

Enter password:
************

Output:
File successfully decrypted.

---

## Error Scenarios

### Wrong Password
Output:
Invalid password or corrupted file.

### File Not Found
Output:
Input file does not exist.

End of document.
