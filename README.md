# zault

A command-line credential manager written in Zig.

## Installation

```bash
zig build -Doptimize=ReleaseSafe
```

Binary will be at `zig-out/bin/zault`. Requires Zig 0.15+.

## Usage

```bash
# Create a vault
zault init

# Add credentials
zault add github.com -u myuser

# Retrieve (copies to clipboard)
zault get github.com

# List all items
zault list

# TOTP
zault totp add github.com
zault totp github.com

# Generate password
zault generate
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new vault |
| `add <name>` | Add a credential |
| `get <name>` | Retrieve and copy to clipboard |
| `list` | List all items |
| `delete <name>` | Remove an item |
| `generate` | Generate a password |
| `totp add <name>` | Add TOTP secret |
| `totp <name>` | Get TOTP code |
| `totp list` | List items with TOTP |
| `passkey list` | List passkeys |
| `passkey show <name>` | Show passkey details |
| `unlock` | Unlock vault (start agent) |
| `lock` | Lock vault (stop agent) |

## Security

- **Key Derivation:** Argon2id
- **Encryption:** XChaCha20-Poly1305
- **TOTP:** HMAC-SHA1/SHA256/SHA512

Sensitive data uses locked memory (`mlock`) and is zeroed before deallocation.

Vault stored at `~/.local/share/zault/vault.zault`.

## Development

```bash
zig build        # build
zig build test   # run tests
```

## License

MIT
