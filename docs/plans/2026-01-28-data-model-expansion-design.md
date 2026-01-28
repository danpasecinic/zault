# Data Model Expansion Design

Date: 2026-01-28

## Overview

Expand zault's data model from a basic credential store to a full-featured password manager comparable to 1Password/Bitwarden. This enables building a native app with rich item types, organization, and search.

## Goals

- Support all common item types (login, card, identity, secure note, SSH keys, etc.)
- Hybrid custom fields (typed categories + flexible user fields)
- Organization via folders (hierarchical) and tags (flat, multi-assign)
- Full-text fuzzy search across all fields
- Automatic password history tracking
- Favorites and recents for quick access

## Non-Goals

- Cloud sync (future work)
- Sharing/multi-user (future work)
- Browser extension/autofill (future work)
- Biometrics integration (future work)

---

## Core Item Model

Replace current `Entry` with a richer `Item` structure:

```zig
pub const Item = struct {
    // Identity
    id: Uuid,
    name: []const u8,

    // Type-specific data
    item_type: ItemType,
    data: ItemData,

    // Organization
    folder_id: ?Uuid,
    tags: []const []const u8,
    favorite: bool,

    // Custom fields (hybrid approach)
    fields: []CustomField,

    // Attachments
    attachments: []Attachment,

    // History & audit
    password_history: []PasswordHistoryEntry,
    created_at: i64,
    modified_at: i64,
    last_accessed_at: ?i64,
    access_count: u32,

    // Soft delete
    deleted_at: ?i64,
};

pub const ItemType = enum(u8) {
    login = 1,
    secure_note = 2,
    card = 3,
    identity = 4,
    ssh_key = 5,
    api_credential = 6,
    database = 7,
    wifi = 8,
    license = 9,
};
```

---

## Item Type Data Structures

### Login

```zig
pub const LoginData = struct {
    username: ?[]const u8,
    password: ?[]const u8,
    uris: []Uri,
    totp: ?TotpData,
    passkeys: []PasskeyData,
};

pub const Uri = struct {
    uri: []const u8,
    match_type: UriMatchType,
};

pub const UriMatchType = enum(u8) {
    domain = 0,
    host = 1,
    starts_with = 2,
    exact = 3,
    regex = 4,
    never = 5,
};
```

### Card

```zig
pub const CardData = struct {
    cardholder_name: ?[]const u8,
    number: ?[]const u8,
    brand: ?CardBrand,
    exp_month: ?u8,
    exp_year: ?u16,
    cvv: ?[]const u8,
    pin: ?[]const u8,
};

pub const CardBrand = enum(u8) {
    visa = 1,
    mastercard = 2,
    amex = 3,
    discover = 4,
    diners = 5,
    jcb = 6,
    unionpay = 7,
    other = 255,
};
```

### Identity

```zig
pub const IdentityData = struct {
    title: ?[]const u8,
    first_name: ?[]const u8,
    middle_name: ?[]const u8,
    last_name: ?[]const u8,
    email: ?[]const u8,
    phone: ?[]const u8,
    address: ?AddressData,
    ssn: ?[]const u8,
    passport: ?[]const u8,
    license_number: ?[]const u8,
    company: ?[]const u8,
    job_title: ?[]const u8,
};

pub const AddressData = struct {
    street1: ?[]const u8,
    street2: ?[]const u8,
    city: ?[]const u8,
    state: ?[]const u8,
    postal_code: ?[]const u8,
    country: ?[]const u8,
};
```

### SSH Key

```zig
pub const SshKeyData = struct {
    private_key: []const u8,
    public_key: []const u8,
    fingerprint: []const u8,
    key_type: SshKeyType,
    passphrase: ?[]const u8,
};

pub const SshKeyType = enum(u8) {
    ed25519 = 1,
    rsa = 2,
    ecdsa = 3,
    dsa = 4,
};
```

### Secure Note

```zig
pub const SecureNoteData = struct {
    // Notes stored in Item.notes field
    // This struct exists for type consistency
};
```

### API Credential

```zig
pub const ApiCredentialData = struct {
    api_key: ?[]const u8,
    api_secret: ?[]const u8,
    endpoint: ?[]const u8,
    documentation_url: ?[]const u8,
};
```

### Database

```zig
pub const DatabaseData = struct {
    db_type: DatabaseType,
    host: ?[]const u8,
    port: ?u16,
    database: ?[]const u8,
    username: ?[]const u8,
    password: ?[]const u8,
    connection_string: ?[]const u8,
    sid: ?[]const u8,
};

pub const DatabaseType = enum(u8) {
    postgresql = 1,
    mysql = 2,
    mariadb = 3,
    sqlite = 4,
    mongodb = 5,
    redis = 6,
    oracle = 7,
    sqlserver = 8,
    other = 255,
};
```

### WiFi

```zig
pub const WifiData = struct {
    ssid: []const u8,
    password: ?[]const u8,
    security: WifiSecurity,
    hidden: bool,
};

pub const WifiSecurity = enum(u8) {
    none = 0,
    wep = 1,
    wpa = 2,
    wpa2 = 3,
    wpa3 = 4,
};
```

### License

```zig
pub const LicenseData = struct {
    license_key: ?[]const u8,
    product_name: ?[]const u8,
    version: ?[]const u8,
    publisher: ?[]const u8,
    email: ?[]const u8,
    purchase_date: ?i64,
    expiration_date: ?i64,
};
```

---

## Custom Fields

```zig
pub const CustomField = struct {
    name: []const u8,
    value: ?[]const u8,
    field_type: FieldType,
    linked_id: ?LinkedFieldId,
};

pub const FieldType = enum(u8) {
    text = 0,
    hidden = 1,
    boolean = 2,
    url = 3,
    email = 4,
    date = 5,
    month_year = 6,
    phone = 7,
    totp = 8,
    linked = 9,
};

pub const LinkedFieldId = enum(u8) {
    // Login
    username = 1,
    password = 2,

    // Card
    cardholder = 3,
    card_number = 4,
    exp_month = 5,
    exp_year = 6,
    cvv = 7,

    // Identity
    full_name = 8,
    email = 9,
    phone = 10,
    address = 11,
};
```

---

## Organization

### Folders

```zig
pub const Folder = struct {
    id: Uuid,
    name: []const u8,
    parent_id: ?Uuid,
    created_at: i64,
    modified_at: i64,
};
```

### Tags

```zig
pub const Tag = struct {
    id: Uuid,
    name: []const u8,
    color: ?[]const u8,
};
```

---

## Vault Structure

```zig
pub const Vault = struct {
    allocator: std.mem.Allocator,
    header: VaultHeader,

    items: std.ArrayList(Item),
    folders: std.ArrayList(Folder),
    tags: std.ArrayList(Tag),

    // Indexes
    items_by_folder: std.AutoHashMap(Uuid, std.ArrayList(*Item)),
    items_by_tag: std.AutoHashMap(Uuid, std.ArrayList(*Item)),

    // Quick access
    recent_items: RingBuffer(*Item, 20),

    // Search
    search_index: SearchIndex,

    // State
    is_locked: bool,
    path: []const u8,
    derived_key: ?[32]u8,

    // Methods
    pub fn getItemsByFolder(self: *Self, folder_id: ?Uuid) []const *Item;
    pub fn getItemsByTag(self: *Self, tag_id: Uuid) []const *Item;
    pub fn getFavorites(self: *Self) []const *Item;
    pub fn getRecents(self: *Self) []const *Item;
    pub fn getDeleted(self: *Self) []const *Item;
    pub fn search(self: *Self, query: []const u8) ![]const *Item;

    pub fn addItem(self: *Self, item: Item) !void;
    pub fn updateItem(self: *Self, item: *Item) !void;
    pub fn deleteItem(self: *Self, item_id: Uuid, permanent: bool) !void;
    pub fn restoreItem(self: *Self, item_id: Uuid) !void;
};
```

---

## Search

Trigram-based fuzzy search index:

```zig
pub const SearchIndex = struct {
    allocator: std.mem.Allocator,
    trigrams: std.StringHashMap(std.ArrayList(Uuid)),

    pub fn index(self: *Self, item: *const Item) !void;
    pub fn remove(self: *Self, item_id: Uuid) void;
    pub fn search(self: *Self, query: []const u8, limit: usize) ![]const Uuid;
    pub fn rebuild(self: *Self, items: []const Item) !void;
};
```

Indexed fields per item type:
- All: name, notes, custom field names/values (non-hidden), tags
- Login: username, URI hosts
- Card: cardholder name, last 4 digits
- Identity: all name fields, email, company
- SSH Key: fingerprint, key type
- Database: host, database name
- WiFi: SSID

---

## Password History

```zig
pub const PasswordHistoryEntry = struct {
    password: []const u8,
    changed_at: i64,
};
```

Behavior:
- Automatically saved when password field changes
- Keep last 10 entries per item
- Stored encrypted alongside other sensitive data
- Applies to: login password, card PIN, SSH passphrase, database password, WiFi password

---

## Attachments

```zig
pub const Attachment = struct {
    id: Uuid,
    filename: []const u8,
    size: u64,
    mime_type: ?[]const u8,
    key: [32]u8,  // Per-attachment encryption key
    created_at: i64,
};
```

Attachments stored as separate encrypted files in vault directory, referenced by ID.

---

## Migration Path

1. Bump vault version from 1 to 2
2. On open, detect version and migrate:
   - `password` entries become `login` items
   - `totp` entries become `login` items with TOTP field
   - `passkey` entries become `login` items with passkeys array
3. New serializer handles both reading v1 (with migration) and v2

---

## Implementation Phases

### Phase 1: Core Data Model
- New item types and structures
- Updated serializer (v2 format)
- Migration from v1
- Basic CRUD operations

### Phase 2: Organization
- Folders (nested)
- Tags
- Favorites
- Recents tracking

### Phase 3: Search
- Trigram index implementation
- Full-text search across fields
- Fuzzy matching

### Phase 4: CLI Updates
- New commands for item types
- Folder/tag management
- Search command

### Phase 5: Attachments
- File storage
- Per-attachment encryption
- Size limits

---

## Security Considerations

- All sensitive fields (passwords, keys, SSN, card numbers) stored encrypted
- Custom fields with `hidden` type treated as sensitive
- Password history encrypted
- Attachments encrypted with per-file keys
- Search index only contains non-sensitive data
