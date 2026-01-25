# Architecture

## Overview

zault is built with a layered architecture, separating concerns for maintainability and security.

```mermaid
graph TB
    subgraph UI["User Interfaces"]
        CLI[CLI]
        TUI[TUI]
        Bridge[Browser Bridge]
    end

    subgraph Services["Services"]
        Creds[Credentials]
        TOTP[TOTP]
        Passkeys[Passkeys]
        Gen[Generator]
        Clip[Clipboard]
    end

    subgraph Core["Core"]
        Vault[Vault]
        Entry[Entry]
        MasterKey[MasterKey]
        Config[Config]
    end

    subgraph Crypto["Crypto"]
        Argon2[Argon2]
        XChaCha[XChaCha20]
        HMAC[HMAC]
        ECDSA[ECDSA]
        Random[Random]
    end

    subgraph Storage["Memory & Storage"]
        SecAlloc[SecureAllocator]
        Format[VaultFormat]
        Serial[Serialization]
        Paths[Paths]
    end

    UI --> Services
    Services --> Core
    Core --> Crypto
    Crypto --> Storage
```

## Module Responsibilities

### CLI (`src/cli/`)

Command-line interface parsing and execution.

- `root.zig` - Argument parsing, command dispatch
- `commands.zig` - Individual command implementations
- `output.zig` - Formatted output (text, JSON)

### TUI (`src/tui/`)

Terminal user interface with interactive features.

- `app.zig` - Application state, event loop
- `views/` - Different screens (entries, TOTP, passkeys)
- `widgets/` - Reusable UI components

### Core (`src/core/`)

Central data structures and vault management.

- `vault.zig` - Vault encryption/decryption, CRUD operations
- `entry.zig` - Entry types (password, TOTP, passkey)
- `master_key.zig` - Key derivation and management
- `config.zig` - Application configuration

### Services (`src/services/`)

Business logic for specific features.

- `credentials.zig` - Password entry management
- `totp.zig` - TOTP generation and verification
- `passkey.zig` - WebAuthn credential handling
- `generator.zig` - Password/passphrase generation
- `clipboard.zig` - Clipboard operations with auto-clear
- `agent.zig` - Background agent for credential caching (ssh-agent style)

### Crypto (`src/crypto/`)

Cryptographic operations wrappers.

- `argon2.zig` - Key derivation (via libsodium)
- `xchacha.zig` - Vault encryption
- `hmac.zig` - TOTP calculation
- `ecdsa.zig` - Passkey signing
- `random.zig` - Secure random generation

### Memory (`src/memory/`)

Secure memory handling.

- `secure_allocator.zig` - mlock + zeroing allocator
- `secret.zig` - Secret wrapper type

### Storage (`src/storage/`)

Persistence and file formats.

- `format.zig` - Vault binary format
- `serialization.zig` - Entry serialization
- `paths.zig` - XDG path resolution

### WebAuthn (`src/webauthn/`)

Passkey/FIDO2 support.

- `cbor.zig` - CBOR encoding/decoding
- `authenticator.zig` - Authenticator data structures
- `attestation.zig` - Attestation handling
- `assertion.zig` - Assertion signing

### Bridge (`src/bridge/`)

Browser integration.

- `native_messaging.zig` - Chrome/Firefox native messaging
- `protocol.zig` - JSON-RPC protocol

## Data Flow

### Adding a Password

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant CredService as Credentials Service
    participant Vault
    participant Storage

    User->>CLI: zault add github.com
    CLI->>CredService: create entry
    CredService->>CredService: validate input
    CredService->>Vault: add entry
    Vault->>Vault: serialize entries
    Vault->>Vault: encrypt with master key
    Vault->>Storage: write to disk
    Storage-->>User: success
```

### Getting a TOTP Code

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Vault
    participant TOTP as TOTP Service
    participant Clipboard

    User->>CLI: zault totp github
    CLI->>Vault: find TOTP entry
    Vault-->>TOTP: entry data
    TOTP->>TOTP: decode secret
    TOTP->>TOTP: calculate HMAC
    TOTP->>TOTP: truncate to digits
    TOTP->>Clipboard: copy code
    Clipboard->>Clipboard: schedule clear (45s)
    TOTP-->>User: display code + time remaining
```

### Passkey Authentication

```mermaid
sequenceDiagram
    participant Browser
    participant Bridge as Native Messaging
    participant Passkey as Passkey Service
    participant Vault

    Browser->>Bridge: WebAuthn request
    Bridge->>Bridge: parse JSON-RPC
    Bridge->>Bridge: validate origin
    Bridge->>Passkey: authenticate
    Passkey->>Vault: find credential
    Vault-->>Passkey: credential data
    Passkey->>Passkey: sign challenge
    Passkey->>Vault: increment counter
    Vault->>Vault: save updated entry
    Passkey-->>Bridge: signed assertion
    Bridge-->>Browser: response
```

### Agent-Based Unlock

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Agent as Agent Service
    participant Vault

    Note over User,Vault: Initial Unlock
    User->>CLI: zault unlock
    CLI->>Vault: unlock with password
    Vault->>Vault: derive key (Argon2)
    CLI->>Agent: start server with key
    Agent->>Agent: fork to background
    Agent->>Agent: listen on Unix socket

    Note over User,Vault: Subsequent Commands
    User->>CLI: zault list
    CLI->>Agent: GET_KEY (via socket)
    Agent->>Agent: verify peer credentials
    Agent-->>CLI: derived key
    CLI->>Vault: unlock with key
    Vault-->>CLI: entries
    CLI-->>User: display entries
```

## Error Handling

All errors are strongly typed using Zig's error unions.

```zig
const VaultError = error{
    VaultNotFound,
    VaultLocked,
    VaultCorrupted,
    InvalidMasterPassword,
    EntryNotFound,
    EntryAlreadyExists,
    IoError,
    CryptoError,
};
```

Errors propagate up to the UI layer, which formats them for display.

## Testing Strategy

1. **Unit tests** - Each module has tests in the same file
2. **Integration tests** - `tests/` directory
3. **Fuzzing** - Parsing code should be fuzzed
4. **Property tests** - Crypto round-trips

Run tests:
```bash
zig build test
```
