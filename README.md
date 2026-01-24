# zault

A secure credential manager written in Zig. Passwords, TOTP, and Passkeys.

## Features

- **Passwords** - Encrypted vault with Argon2id + XChaCha20-Poly1305
- **TOTP** - Time-based one-time passwords (2FA)
- **Passkeys** - WebAuthn/FIDO2 software authenticator
- **Clipboard** - Auto-clearing clipboard integration
- **TUI** - Full terminal UI with fuzzy search
- **Browser** - Native messaging for passkey authentication

## Installation

### From source

```bash
zig build -Doptimize=ReleaseSafe
```

The binary will be in `zig-out/bin/zault`.

### Requirements

- Zig 0.13.0 or later

## Quick Start

```bash
# Initialize a new vault
zault init

# Add a password
zault add github.com -u myuser

# Get a password (copies to clipboard)
zault get github.com

# Add TOTP secret
zault totp add github.com

# Get current TOTP code
zault totp github.com

# Generate a secure password
zault generate

# Launch TUI
zault
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new vault |
| `add <name>` | Add a new credential |
| `get <name>` | Retrieve and copy credential |
| `list` | List all entries |
| `delete <name>` | Remove an entry |
| `generate` | Generate a secure password |
| `totp add <name>` | Add TOTP secret |
| `totp <name>` | Get current TOTP code |
| `passkey list` | List stored passkeys |
| `lock` | Lock the vault |
| `export` | Export vault (encrypted) |
| `import` | Import credentials |

## Security

### Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Key Derivation | Argon2id |
| Encryption | XChaCha20-Poly1305 |
| TOTP | HMAC-SHA1/SHA256/SHA512 |
| Passkeys | Ed25519 / ECDSA P-256 |

### Memory Security

- Sensitive data is allocated in locked memory (`mlock`)
- All secrets are zeroed before deallocation
- No garbage collector - deterministic memory management

### Vault Format

The vault is stored as an encrypted binary file at `~/.config/zault/vault.zault`.

See [SECURITY.md](docs/SECURITY.md) for detailed security information.

## Development

```bash
# Build
zig build

# Run tests
zig build test

# Run with arguments
zig build run -- --help

# Generate docs
zig build docs
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [libsodium](https://libsodium.org/) - Cryptographic library
- [zig-clap](https://github.com/Hejsil/zig-clap) - CLI argument parsing
- [libvaxis](https://github.com/rockorager/libvaxis) - TUI framework
