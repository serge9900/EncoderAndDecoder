# Security information

LumiAi is a personal application and has **not undergone a professional security audit**.

## Modern format

Messages beginning with `LUMIAI1:` use **AES-256-GCM** with a fresh 16-byte salt and 12-byte nonce per encryption. The 256-bit AES key is derived from the password using PBKDF2-HMAC-SHA256 with 600,000 iterations. AES-GCM authenticates ciphertext and detects wrong passwords or message modifications. Password strength still matters; use a long, unique passphrase.

## Legacy mode

The original algorithm is kept solely for decoding old messages. It is **not** cryptographically secure and cannot authenticate passwords. Do not use it for sensitive messages.

## Data handling and limitations

- The GUI stores only its language preference in the local settings JSON. Text, passwords and messages are not written to that settings file.
- Clipboard contents can be read by other software; clearing a text box doesn't erase all memory buffers or clipboard history.
- Exporting a decrypted `.txt` file exposes the plaintext to anyone with access to that file.
- Do not treat LumiAi as a replacement for independently reviewed end-to-end encrypted communications systems.

## Reporting issues

Open a GitHub issue **without including real secrets, private keys, sensitive messages, or passwords**.
