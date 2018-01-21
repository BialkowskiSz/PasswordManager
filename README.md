## Python CLI Password Manager

 ##### Personal use Password Manager developed for ease of use and to further my knowledge of symmetric block and stream ciphers.

### Functionality:
- AES-256-GCM-HMAC Encryption
  - Pycryptodome library.
  - HMAC ensures integrity of file during decryption.
  - AES-GCM 32 byte random nonce generated on every encryption.
* scrypt password-based key derivation
  * Implements further password security by applying a costly key derivation function.
  * Key is then used as AES key for encrypting of Password Vault.
- Random Password Generator
  - Urandom for cryptographically secure functionality.
* JSON format
