<div align="center">

# 🔒 Ciphers

**A simple, secure GTK3 desktop application for encrypting and decrypting files
with modern authenticated encryption.**

[![Version](https://img.shields.io/badge/version-1.0.2-00e5ff?labelColor=0e1726)](https://github.com/effjy/ciphers/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-39ff14?labelColor=0e1726)](https://github.com/effjy/ciphers/blob/main/LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-9fd6e6?labelColor=0e1726)
![Toolkit: GTK3](https://img.shields.io/badge/GTK-3-9fd6e6?labelColor=0e1726)
![Crypto: libsodium + Argon2id](https://img.shields.io/badge/crypto-libsodium%20%2B%20Argon2id-00b3c4?labelColor=0e1726)
![AEAD: AES-256-GCM | XChaCha20 | ChaCha20](https://img.shields.io/badge/AEAD-AES--256--GCM%20%7C%20XChaCha20%20%7C%20ChaCha20-ff426f?labelColor=0e1726)
<br>
[![Issues](https://img.shields.io/github/issues/effjy/ciphers?color=ff426f&labelColor=0e1726)](https://github.com/effjy/ciphers/issues)
[![Last commit](https://img.shields.io/github/last-commit/effjy/ciphers?color=39ff14&labelColor=0e1726)](https://github.com/effjy/ciphers/commits)

Author: **Jean-Francois Lachance-Caumartin**

🔗 **[github.com/effjy/ciphers](https://github.com/effjy/ciphers/)**

</div>

## Screenshot

<div align="center">

![Ciphers screenshot](screenshot.png)

</div>

## Features

- Encrypt and decrypt any file with a password.
- Authenticated encryption with **AES-256-GCM** (default), **XChaCha20-Poly1305**
  or **ChaCha20-Poly1305**.
- **Argon2id** key derivation with a configurable strength setting:
  - **Basic** — 256 MiB
  - **Medium** — 1 GiB, parallel *(minimum recommended)*
  - **Strong** — 4 GiB, parallel
- Chunked streaming encryption with per-chunk authentication, providing
  tamper, reordering and truncation detection.
- **Hardened memory handling** — passwords, derived keys and plaintext are
  held in locked memory that is never written to the swap file and never
  captured in a core dump, and is zeroed after use. The password field itself
  is backed by libsodium guarded memory.
- Optional **password reveal** checkbox for typing long passphrases.
- Background worker thread so the key-derivation step never freezes the UI.

## Prerequisites

You need a C compiler, `make`, and the development packages for GTK3,
libsodium and libargon2.

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install build-essential pkg-config \
    libgtk-3-dev libsodium-dev libargon2-dev
```

### Fedora

```bash
sudo dnf install gcc make pkgconf-pkg-config \
    gtk3-devel libsodium-devel libargon2-devel
```

## Building

```bash
make
```

This produces the `ciphers` binary in the project directory. You can run it
directly with `./ciphers`.

## Installing

To install globally so it appears in the Ubuntu applications menu (with its
icon) and shows its icon in the window/taskbar:

```bash
sudo make install
```

This installs:

| File | Destination |
|------|-------------|
| `ciphers` binary    | `/usr/local/bin/ciphers` |
| Application icon    | `/usr/local/share/icons/hicolor/scalable/apps/ciphers.svg` |
| Menu entry          | `/usr/local/share/applications/ciphers.desktop` |

The desktop database and icon cache are refreshed automatically. The app
then appears in your activities/applications menu as **Ciphers**.

To uninstall:

```bash
sudo make uninstall
```

> Installation prefix is configurable, e.g. `sudo make install PREFIX=/usr`.

## Usage

1. Launch **Ciphers** from the applications menu, or run `ciphers`.
2. Choose **Encrypt** or **Decrypt**.
3. Pick the **Input file** and the **Output file** (use the *Browse…* buttons).
4. When encrypting:
   - Select the **Cipher** (AES-256-GCM by default; XChaCha20-Poly1305 or
     ChaCha20-Poly1305 also available).
   - Select the **Key strength** (Medium is the minimum recommended).
   - On decryption these are read automatically from the file header.
5. Type your **Password**. Tick **Reveal** to display it while typing.
6. Click **Encrypt** / **Decrypt**. A progress bar shows the operation; key
   derivation can take a moment at higher strengths.

The **About** button shows version, author and the full feature list.

## File format

Encrypted files begin with the magic header `CIPHERS\0` followed by a format
version, the cipher id, the Argon2id parameters (iterations, memory,
parallelism), a random salt and a random base nonce. The payload is split
into 64 KiB chunks, each encrypted as an independent AEAD frame whose
associated data binds the chunk's position and an end-of-stream flag — so
tampering, reordering or truncation is always detected on decryption.

If decryption fails, the password is wrong or the file has been corrupted or
tampered with; the partial output file is removed automatically.

## Security notes

- Encryption keys are derived with Argon2id and wiped from memory after use.
- Authenticated encryption (AEAD) guarantees both confidentiality and
  integrity — modified ciphertext will not decrypt.
- Choose **Medium** or **Strong** key strength for sensitive data. Higher
  strengths use more RAM during key derivation (1 GiB / 4 GiB).
- Secrets are kept off disk: core dumps are disabled, and passwords, keys and
  plaintext are stored in locked, non-dumpable memory and zeroed after use.
  Note that GTK itself may still hold short-lived copies of typed text (for
  on-screen rendering, the clipboard or the input method) in ordinary memory,
  so this hardening reduces but cannot fully eliminate exposure.

## License

MIT.
