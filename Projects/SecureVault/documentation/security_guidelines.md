# Secure File Vault - Security Guidelines

## FORBIDDEN PRACTICES
- Logging passwords or derived keys
- Storing sensitive data in plaintext
- Hardcoding cryptographic constants or secrets
- Reusing salts
- Displaying stack traces to end users

## MANDATORY PRACTICES
- Use getpass.getpass() for password input
- Generate salts using os.urandom()
- Apply PBKDF2-HMAC-SHA256 with 200000 iterations minimum
- Perform code review on crypto-related code only by the security architect

## PASSWORD POLICY
Minimum requirements:
- 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

## LOGGING POLICY
- Logs must never contain:
  - passwords
  - encryption keys
  - decrypted content
- Only high-level sanitized error messages are allowed.

## EXCEPTION HANDLING
- No raw stack traces in production mode
- Errors must be generic and non-revealing

## CODE CONTROL
Any modification to:
- crypto_core.py
- key_management.py  

Must be reviewed and approved by the security architect.

End of document.
