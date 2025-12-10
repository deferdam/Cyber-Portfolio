# Secure File Vault - Threat Model

## Objective
Prevent unauthorized access to encrypted file contents by enforcing strong cryptography and key derivation.

## Assets
- Plaintext data
- User password
- Derived encryption key

## Threat Actors
- Data thief with access to encrypted files
- Attacker attempting brute-force

## Attack Vectors

### Offline Brute Force
Mitigation: Strong KDF and password policy

### File Tampering
Mitigation: Authenticated encryption and structured parsing

### Malware on Host
Out of Scope

## Security Guarantees
- Confidentiality without password
- Tamper detection

## Assumptions
- Secure OS environment
- Reliable RNG

## Residual Risks
- Weak passwords
- Compromised machine

End of document.
