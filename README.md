# passmngr

A simple command-line password manager written in C++17.

All entries (name, URL, user, password, info) are stored in a single encrypted
vault file at `~/.pass.json` (chmod `0600`). The file is authenticated-encrypted
with **AES-256-GCM**; the encryption key is derived from your master password
using **PBKDF2-HMAC-SHA256** (600,000 iterations, random 128-bit salt). A fresh
random nonce is used for every save, and the plaintext never touches disk.

## Features

- `init`, `add`, `list`, `show`, `edit`, `rm`, `pw`, `gen` commands
- Hidden password input (echo disabled)
- Random password generation from the OS RNG (OpenSSL `RAND_bytes`)
- Master-password change without re-entering entries
- Deterministic, dependency-light JSON serialization (no external JSON lib)
- No plaintext password ever stored in the vault file

## Requirements

- C++17 compiler (`g++` or `clang++`)
- GNU Make
- OpenSSL 1.1.1+ development headers (`openssl-devel` / `libssl-dev`)

## Build

```sh
make            # builds ./passmngr
make install    # installs to /usr/local/bin (sudo make install for system-wide)
make clean
```

## Usage

```sh
passmngr init                          # create the vault (master password >= 8 chars)
passmngr add github --url https://github.com --user me --gen
passmngr add gmail --user me           # prompts for missing fields
passmngr list                          # show all entries
passmngr show github                   # show entry (password masked)
passmngr show github -p                # show entry including password
passmngr edit github                   # update fields (empty keeps current)
passmngr rm github                     # remove an entry
passmngr pw                            # change the master password
passmngr gen 32                        # print a 32-char random password
```

`init` must be run once; every other command asks for the master password to
decrypt the vault.

## Vault file format

`~/.pass.json` is JSON wrapping the ciphertext and its key material:

```json
{
  "version": 1,
  "cipher": "aes-256-gcm",
  "kdf": {
    "algo": "pbkdf2-sha256",
    "iterations": 600000,
    "salt": "<base64>"
  },
  "iv": "<base64>",
  "tag": "<base64>",
  "data": "<base64>"
}
```

`data` is the AES-256-GCM ciphertext of an inner JSON document:

```json
{ "entries": [ { "name": "", "url": "", "user": "", "password": "", "info": "" } ] }
```

Tampering or an incorrect master password fails the GCM authentication check
and is reported as "wrong master password or corrupted vault".

## Project layout

```
Makefile
README.md
.gitignore
src/
  main.cpp     CLI entry point and commands
  storage.h/.cpp  vault encryption/serialization (Vault, Entry)
  crypto.h/.cpp   AES-256-GCM + PBKDF2 + base64 via OpenSSL EVP
  json.h/.cpp     minimal self-contained JSON parser/serializer
```

## Security notes

- The master password is the single point of failure: choose a strong one.
- The vault file is written with mode `0600`; keep your home directory private.
- PBKDF2 iteration count (600,000) follows OWASP guidance for PBKDF2-SHA256.
- Consider a key file or hardware token for higher-assurance setups.
