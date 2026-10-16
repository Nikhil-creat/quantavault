# Security policy
## Model
Encryption runs client-side (AES-256-GCM, PBKDF2-SHA256 250,000 rounds, random salt and nonce per item). The server never receives passphrases or keys.
## Limits (be honest with users)
- Lost passphrase = lost data. No recovery.
- The browser demo does not verify passkeys server-side and keeps its audit log in memory.
- Post-quantum hybrid key exchange (ML-KEM + X25519) is planned, not implemented.
- The Groq key pasted by a visitor is stored in that browser's localStorage; use a key with limited quota.
- The unlock lockout (3 wrong tries, then growing delays) is enforced in the browser only. Someone who copies the raw browser data can still guess offline, so use a long random passphrase.
- Tasks are encrypted with the vault key and included in encrypted backups.
## Reporting
Email sriramojunikhil66@gmail.com with details. Please allow 7 days before disclosure.
