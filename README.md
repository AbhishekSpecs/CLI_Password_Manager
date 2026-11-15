# CLI Password Manager

A Python command-line password manager that encrypts all credential fields with AES-256-GCM. It uses PBKDF2-HMAC-SHA256 to derive a key from a master password and stores the encrypted vault as JSON.

## Requirements

- Python 3.10 or newer recommended
- `cryptography`

## Setup (Windows PowerShell)

```powershell
cd "path\to\cli_password_manager"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can skip virtual-environment activation and use the Python interpreter where `cryptography` is installed.

## Commands

Create a vault:

```powershell
python main.py init
```

Add a credential (website, username, and password are prompted; account password is hidden):

```powershell
python main.py add
```

List saved sites:

```powershell
python main.py list
```

Retrieve one entry (the password will be displayed on screen):

```powershell
python main.py get example.com
```

Delete an entry:

```powershell
python main.py delete example.com
```

Change the master password and re-encrypt all entries:

```powershell
python main.py change-master
```

Use a different vault location:

```powershell
python main.py --vault "D:\Secure\vault.json" init
python main.py --vault "D:\Secure\vault.json" list
```

## Data files

- `vault.json`: salt, encrypted master-password verifier, and encrypted credential records.
- `vault.json.lock.json`: basic persistent failed-attempt lockout state.

Credential site names, usernames, and passwords are all encrypted. The salt is public metadata. Every encrypted record has a fresh random 96-bit nonce, ciphertext, and 128-bit authentication tag. Never reuse a nonce with the same key; this implementation generates a new random nonce for each encryption.

## Security notes

- Keep an offline backup of `vault.json`. If it is lost or the master password is forgotten, the credentials cannot be recovered.
- Do not put master passwords or account passwords in command-line arguments.
- The lockout is a basic local deterrent, not protection against an attacker who can edit/delete local files, copy the vault and attack it offline, or run modified code.
- AES-GCM detects ciphertext tampering. PBKDF2 slows password guessing but does not make a weak master password safe; use a long, unique passphrase.
- Python cannot reliably guarantee that immutable strings/bytes are wiped from process memory. This program minimizes unnecessary copies but does not claim secure memory zeroization.
- Atomic replacement helps avoid partially written JSON files, but it is not a substitute for backups or disk-level protections.
- Retrieved passwords are printed in plaintext by request. Be aware of shoulder-surfing, terminal scrollback, and screen recordings.

## Limitations / next improvements

This is an educational local CLI project. For stronger production security, consider a reviewed threat model, OS keychain integration, hardened file permissions, a carefully designed lockout strategy, and independent security review.
