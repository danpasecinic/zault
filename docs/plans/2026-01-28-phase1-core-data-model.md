# Phase 1: Core Data Model Implementation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current 3-type Entry system with a 9-type Item system supporting the full password manager data model.

**Architecture:** New `src/core/item.zig` defines all item types. New `src/core/serializer_v2.zig` handles the new format. The vault header version bumps from 1 to 2. On load, v1 vaults are migrated to v2 in memory and saved in v2 format.

**Tech Stack:** Zig 0.15, no new dependencies.

---

## Task 1: Create UUID Type

**Files:**
- Create: `src/core/uuid.zig`
- Test: `src/core/uuid.zig` (inline tests)

**Step 1: Write the failing test**

Create `src/core/uuid.zig` with test at bottom:

```zig
const std = @import("std");

pub const Uuid = struct {
    bytes: [16]u8,

    pub fn generate() Uuid {
        var bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&bytes);
        // Set version 4 (random) and variant bits
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        return .{ .bytes = bytes };
    }

    pub fn fromBytes(bytes: [16]u8) Uuid {
        return .{ .bytes = bytes };
    }

    pub fn eql(self: Uuid, other: Uuid) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn isZero(self: Uuid) bool {
        return std.mem.eql(u8, &self.bytes, &[_]u8{0} ** 16);
    }

    pub const zero = Uuid{ .bytes = [_]u8{0} ** 16 };
};

test "uuid generate produces unique values" {
    const a = Uuid.generate();
    const b = Uuid.generate();
    try std.testing.expect(!a.eql(b));
}

test "uuid zero check" {
    const z = Uuid.zero;
    try std.testing.expect(z.isZero());

    const g = Uuid.generate();
    try std.testing.expect(!g.isZero());
}

test "uuid version 4 format" {
    const u = Uuid.generate();
    // Version should be 4
    try std.testing.expectEqual(@as(u8, 4), (u.bytes[6] >> 4) & 0x0f);
    // Variant should be 10xx
    try std.testing.expectEqual(@as(u8, 2), (u.bytes[8] >> 6) & 0x03);
}
```

**Step 2: Run test to verify it passes**

Run: `zig build test 2>&1 | grep -E "(uuid|PASS|FAIL)"`
Expected: All 3 uuid tests PASS

**Step 3: Commit**

```bash
git add src/core/uuid.zig
git commit -m "feat(core): add UUID type for item identifiers"
```

---

## Task 2: Create Item Types Enum and Base Structures

**Files:**
- Create: `src/core/item.zig`
- Test: `src/core/item.zig` (inline tests)

**Step 1: Create item.zig with enums and base Item struct**

```zig
const std = @import("std");
const Uuid = @import("uuid.zig").Uuid;

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

pub const CustomField = struct {
    name: []const u8,
    value: ?[]const u8,
    field_type: FieldType,

    pub fn deinit(self: *CustomField, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.value) |v| allocator.free(v);
    }
};

pub const PasswordHistoryEntry = struct {
    password: []const u8,
    changed_at: i64,

    pub fn deinit(self: *PasswordHistoryEntry, allocator: std.mem.Allocator) void {
        @memset(@constCast(self.password), 0);
        allocator.free(self.password);
    }
};

pub const Item = struct {
    id: Uuid,
    name: []const u8,
    notes: ?[]const u8,
    item_type: ItemType,
    data: ItemData,
    favorite: bool,
    fields: []CustomField,
    password_history: []PasswordHistoryEntry,
    created_at: i64,
    modified_at: i64,
    last_accessed_at: ?i64,
    access_count: u32,
    deleted_at: ?i64,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.notes) |n| allocator.free(n);

        for (self.fields) |*f| f.deinit(allocator);
        allocator.free(self.fields);

        for (self.password_history) |*h| h.deinit(allocator);
        allocator.free(self.password_history);

        self.data.deinit(allocator);
    }

    pub fn updateLastAccessed(self: *Self) void {
        self.last_accessed_at = std.time.timestamp();
        self.access_count += 1;
    }
};

pub const ItemData = union(ItemType) {
    login: LoginData,
    secure_note: SecureNoteData,
    card: CardData,
    identity: IdentityData,
    ssh_key: SshKeyData,
    api_credential: ApiCredentialData,
    database: DatabaseData,
    wifi: WifiData,
    license: LicenseData,

    pub fn deinit(self: *ItemData, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .login => |*d| d.deinit(allocator),
            .secure_note => {},
            .card => |*d| d.deinit(allocator),
            .identity => |*d| d.deinit(allocator),
            .ssh_key => |*d| d.deinit(allocator),
            .api_credential => |*d| d.deinit(allocator),
            .database => |*d| d.deinit(allocator),
            .wifi => |*d| d.deinit(allocator),
            .license => |*d| d.deinit(allocator),
        }
    }
};

// Placeholder structs - will be filled in next tasks
pub const LoginData = struct {
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,

    pub fn deinit(self: *LoginData, allocator: std.mem.Allocator) void {
        if (self.username) |u| allocator.free(u);
        if (self.password) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
    }
};

pub const SecureNoteData = struct {};

pub const CardData = struct {
    pub fn deinit(_: *CardData, _: std.mem.Allocator) void {}
};

pub const IdentityData = struct {
    pub fn deinit(_: *IdentityData, _: std.mem.Allocator) void {}
};

pub const SshKeyData = struct {
    pub fn deinit(_: *SshKeyData, _: std.mem.Allocator) void {}
};

pub const ApiCredentialData = struct {
    pub fn deinit(_: *ApiCredentialData, _: std.mem.Allocator) void {}
};

pub const DatabaseData = struct {
    pub fn deinit(_: *DatabaseData, _: std.mem.Allocator) void {}
};

pub const WifiData = struct {
    pub fn deinit(_: *WifiData, _: std.mem.Allocator) void {}
};

pub const LicenseData = struct {
    pub fn deinit(_: *LicenseData, _: std.mem.Allocator) void {}
};

test "item type enum values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(ItemType.login));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(ItemType.license));
}

test "field type enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(FieldType.text));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(FieldType.hidden));
}
```

**Step 2: Run test to verify it passes**

Run: `zig build test 2>&1 | grep -E "(item|PASS|FAIL)"`
Expected: PASS

**Step 3: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): add Item type with enums and base structures"
```

---

## Task 3: Implement LoginData with Full Fields

**Files:**
- Modify: `src/core/item.zig`

**Step 1: Write test for LoginData**

Add to `src/core/item.zig`:

```zig
test "login data deinit clears password" {
    const allocator = std.testing.allocator;

    var login = LoginData{
        .username = try allocator.dupe(u8, "user"),
        .password = try allocator.dupe(u8, "secret"),
        .uris = &.{},
        .totp = null,
        .passkeys = &.{},
    };

    login.deinit(allocator);
    // If we get here without crash, deinit worked
}
```

**Step 2: Implement full LoginData**

Replace the placeholder LoginData with:

```zig
pub const TotpAlgorithm = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    sha512 = 3,
};

pub const TotpData = struct {
    secret: []const u8,
    algorithm: TotpAlgorithm = .sha1,
    digits: u8 = 6,
    period: u32 = 30,

    pub fn deinit(self: *TotpData, allocator: std.mem.Allocator) void {
        @memset(@constCast(self.secret), 0);
        allocator.free(self.secret);
    }
};

pub const UriMatchType = enum(u8) {
    domain = 0,
    host = 1,
    starts_with = 2,
    exact = 3,
    regex = 4,
    never = 5,
};

pub const Uri = struct {
    uri: []const u8,
    match_type: UriMatchType = .domain,

    pub fn deinit(self: *Uri, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
    }
};

pub const PasskeyAlgorithm = enum(i32) {
    es256 = -7,
    ed25519 = -8,
    rs256 = -257,
};

pub const PasskeyData = struct {
    credential_id: []const u8,
    private_key: []const u8,
    public_key: []const u8,
    algorithm: PasskeyAlgorithm,
    rp_id: []const u8,
    rp_name: ?[]const u8,
    user_handle: []const u8,
    user_name: ?[]const u8,
    counter: u32,

    pub fn deinit(self: *PasskeyData, allocator: std.mem.Allocator) void {
        allocator.free(self.credential_id);
        @memset(@constCast(self.private_key), 0);
        allocator.free(self.private_key);
        allocator.free(self.public_key);
        allocator.free(self.rp_id);
        if (self.rp_name) |n| allocator.free(n);
        allocator.free(self.user_handle);
        if (self.user_name) |n| allocator.free(n);
    }
};

pub const LoginData = struct {
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    uris: []Uri = &.{},
    totp: ?TotpData = null,
    passkeys: []PasskeyData = &.{},

    pub fn deinit(self: *LoginData, allocator: std.mem.Allocator) void {
        if (self.username) |u| allocator.free(u);
        if (self.password) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
        for (self.uris) |*uri| uri.deinit(allocator);
        if (self.uris.len > 0) allocator.free(self.uris);
        if (self.totp) |*t| {
            var totp = t;
            totp.deinit(allocator);
        }
        for (self.passkeys) |*pk| pk.deinit(allocator);
        if (self.passkeys.len > 0) allocator.free(self.passkeys);
    }

    pub fn hasTotp(self: *const LoginData) bool {
        return self.totp != null;
    }
};
```

**Step 3: Run test**

Run: `zig build test 2>&1 | grep -E "(login|PASS|FAIL)"`
Expected: PASS

**Step 4: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): implement full LoginData with URIs, TOTP, and passkeys"
```

---

## Task 4: Implement CardData

**Files:**
- Modify: `src/core/item.zig`

**Step 1: Write test**

```zig
test "card data deinit clears sensitive fields" {
    const allocator = std.testing.allocator;

    var card = CardData{
        .cardholder_name = try allocator.dupe(u8, "John Doe"),
        .number = try allocator.dupe(u8, "4111111111111111"),
        .cvv = try allocator.dupe(u8, "123"),
        .pin = try allocator.dupe(u8, "1234"),
    };

    card.deinit(allocator);
}
```

**Step 2: Implement CardData**

```zig
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

pub const CardData = struct {
    cardholder_name: ?[]const u8 = null,
    number: ?[]const u8 = null,
    brand: ?CardBrand = null,
    exp_month: ?u8 = null,
    exp_year: ?u16 = null,
    cvv: ?[]const u8 = null,
    pin: ?[]const u8 = null,

    pub fn deinit(self: *CardData, allocator: std.mem.Allocator) void {
        if (self.cardholder_name) |n| allocator.free(n);
        if (self.number) |n| {
            @memset(@constCast(n), 0);
            allocator.free(n);
        }
        if (self.cvv) |c| {
            @memset(@constCast(c), 0);
            allocator.free(c);
        }
        if (self.pin) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
    }

    pub fn lastFour(self: *const CardData) ?[]const u8 {
        if (self.number) |n| {
            if (n.len >= 4) return n[n.len - 4 ..];
        }
        return null;
    }
};
```

**Step 3: Run test**

Run: `zig build test 2>&1 | grep -E "(card|PASS|FAIL)"`
Expected: PASS

**Step 4: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): implement CardData with brand and secure field handling"
```

---

## Task 5: Implement IdentityData

**Files:**
- Modify: `src/core/item.zig`

**Step 1: Write test**

```zig
test "identity data full name" {
    var identity = IdentityData{
        .first_name = "John",
        .middle_name = "Q",
        .last_name = "Public",
    };

    const full = identity.fullName(std.testing.allocator) catch unreachable;
    defer std.testing.allocator.free(full);
    try std.testing.expectEqualStrings("John Q Public", full);
}
```

**Step 2: Implement IdentityData**

```zig
pub const AddressData = struct {
    street1: ?[]const u8 = null,
    street2: ?[]const u8 = null,
    city: ?[]const u8 = null,
    state: ?[]const u8 = null,
    postal_code: ?[]const u8 = null,
    country: ?[]const u8 = null,

    pub fn deinit(self: *AddressData, allocator: std.mem.Allocator) void {
        if (self.street1) |s| allocator.free(s);
        if (self.street2) |s| allocator.free(s);
        if (self.city) |c| allocator.free(c);
        if (self.state) |s| allocator.free(s);
        if (self.postal_code) |p| allocator.free(p);
        if (self.country) |c| allocator.free(c);
    }
};

pub const IdentityData = struct {
    title: ?[]const u8 = null,
    first_name: ?[]const u8 = null,
    middle_name: ?[]const u8 = null,
    last_name: ?[]const u8 = null,
    email: ?[]const u8 = null,
    phone: ?[]const u8 = null,
    address: ?AddressData = null,
    ssn: ?[]const u8 = null,
    passport: ?[]const u8 = null,
    license_number: ?[]const u8 = null,
    company: ?[]const u8 = null,
    job_title: ?[]const u8 = null,

    pub fn deinit(self: *IdentityData, allocator: std.mem.Allocator) void {
        if (self.title) |t| allocator.free(t);
        if (self.first_name) |n| allocator.free(n);
        if (self.middle_name) |n| allocator.free(n);
        if (self.last_name) |n| allocator.free(n);
        if (self.email) |e| allocator.free(e);
        if (self.phone) |p| allocator.free(p);
        if (self.address) |*a| {
            var addr = a;
            addr.deinit(allocator);
        }
        if (self.ssn) |s| {
            @memset(@constCast(s), 0);
            allocator.free(s);
        }
        if (self.passport) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
        if (self.license_number) |l| allocator.free(l);
        if (self.company) |c| allocator.free(c);
        if (self.job_title) |j| allocator.free(j);
    }

    pub fn fullName(self: *const IdentityData, allocator: std.mem.Allocator) ![]const u8 {
        var parts: std.ArrayList([]const u8) = .empty;
        defer parts.deinit(allocator);

        if (self.first_name) |n| try parts.append(allocator, n);
        if (self.middle_name) |n| try parts.append(allocator, n);
        if (self.last_name) |n| try parts.append(allocator, n);

        return std.mem.join(allocator, " ", parts.items);
    }
};
```

**Step 3: Run test**

Run: `zig build test 2>&1 | grep -E "(identity|PASS|FAIL)"`
Expected: PASS

**Step 4: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): implement IdentityData with address and sensitive field handling"
```

---

## Task 6: Implement Remaining Data Types

**Files:**
- Modify: `src/core/item.zig`

**Step 1: Implement SshKeyData, ApiCredentialData, DatabaseData, WifiData, LicenseData**

```zig
pub const SshKeyType = enum(u8) {
    ed25519 = 1,
    rsa = 2,
    ecdsa = 3,
    dsa = 4,
};

pub const SshKeyData = struct {
    private_key: []const u8,
    public_key: []const u8,
    fingerprint: []const u8,
    key_type: SshKeyType,
    passphrase: ?[]const u8 = null,

    pub fn deinit(self: *SshKeyData, allocator: std.mem.Allocator) void {
        @memset(@constCast(self.private_key), 0);
        allocator.free(self.private_key);
        allocator.free(self.public_key);
        allocator.free(self.fingerprint);
        if (self.passphrase) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
    }
};

pub const ApiCredentialData = struct {
    api_key: ?[]const u8 = null,
    api_secret: ?[]const u8 = null,
    endpoint: ?[]const u8 = null,
    documentation_url: ?[]const u8 = null,

    pub fn deinit(self: *ApiCredentialData, allocator: std.mem.Allocator) void {
        if (self.api_key) |k| {
            @memset(@constCast(k), 0);
            allocator.free(k);
        }
        if (self.api_secret) |s| {
            @memset(@constCast(s), 0);
            allocator.free(s);
        }
        if (self.endpoint) |e| allocator.free(e);
        if (self.documentation_url) |d| allocator.free(d);
    }
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

pub const DatabaseData = struct {
    db_type: DatabaseType = .postgresql,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    database: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    connection_string: ?[]const u8 = null,
    sid: ?[]const u8 = null,

    pub fn deinit(self: *DatabaseData, allocator: std.mem.Allocator) void {
        if (self.host) |h| allocator.free(h);
        if (self.database) |d| allocator.free(d);
        if (self.username) |u| allocator.free(u);
        if (self.password) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
        if (self.connection_string) |c| {
            @memset(@constCast(c), 0);
            allocator.free(c);
        }
        if (self.sid) |s| allocator.free(s);
    }
};

pub const WifiSecurity = enum(u8) {
    none = 0,
    wep = 1,
    wpa = 2,
    wpa2 = 3,
    wpa3 = 4,
};

pub const WifiData = struct {
    ssid: []const u8,
    password: ?[]const u8 = null,
    security: WifiSecurity = .wpa2,
    hidden: bool = false,

    pub fn deinit(self: *WifiData, allocator: std.mem.Allocator) void {
        allocator.free(self.ssid);
        if (self.password) |p| {
            @memset(@constCast(p), 0);
            allocator.free(p);
        }
    }
};

pub const LicenseData = struct {
    license_key: ?[]const u8 = null,
    product_name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    publisher: ?[]const u8 = null,
    email: ?[]const u8 = null,
    purchase_date: ?i64 = null,
    expiration_date: ?i64 = null,

    pub fn deinit(self: *LicenseData, allocator: std.mem.Allocator) void {
        if (self.license_key) |k| {
            @memset(@constCast(k), 0);
            allocator.free(k);
        }
        if (self.product_name) |p| allocator.free(p);
        if (self.version) |v| allocator.free(v);
        if (self.publisher) |p| allocator.free(p);
        if (self.email) |e| allocator.free(e);
    }
};
```

**Step 2: Add tests**

```zig
test "ssh key data deinit clears private key" {
    const allocator = std.testing.allocator;

    var ssh = SshKeyData{
        .private_key = try allocator.dupe(u8, "PRIVATE"),
        .public_key = try allocator.dupe(u8, "PUBLIC"),
        .fingerprint = try allocator.dupe(u8, "SHA256:xxx"),
        .key_type = .ed25519,
        .passphrase = try allocator.dupe(u8, "secret"),
    };

    ssh.deinit(allocator);
}

test "wifi data deinit" {
    const allocator = std.testing.allocator;

    var wifi = WifiData{
        .ssid = try allocator.dupe(u8, "MyNetwork"),
        .password = try allocator.dupe(u8, "wifipass"),
        .security = .wpa3,
    };

    wifi.deinit(allocator);
}
```

**Step 3: Run tests**

Run: `zig build test 2>&1 | grep -E "(ssh|wifi|PASS|FAIL)"`
Expected: PASS

**Step 4: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): implement SshKeyData, ApiCredentialData, DatabaseData, WifiData, LicenseData"
```

---

## Task 7: Create Item Factory Functions

**Files:**
- Modify: `src/core/item.zig`

**Step 1: Write test**

```zig
test "create login item" {
    const allocator = std.testing.allocator;

    var item = try createLoginItem(allocator, "github.com", "user", "pass", "https://github.com");
    defer item.deinit(allocator);

    try std.testing.expectEqualStrings("github.com", item.name);
    try std.testing.expectEqual(ItemType.login, item.item_type);
    try std.testing.expectEqualStrings("user", item.data.login.username.?);
}
```

**Step 2: Implement factory functions**

```zig
pub fn createLoginItem(
    allocator: std.mem.Allocator,
    name: []const u8,
    username: ?[]const u8,
    password: ?[]const u8,
    url: ?[]const u8,
) !Item {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);

    const username_copy = if (username) |u| try allocator.dupe(u8, u) else null;
    errdefer if (username_copy) |u| allocator.free(u);

    const password_copy = if (password) |p| try allocator.dupe(u8, p) else null;
    errdefer if (password_copy) |p| allocator.free(p);

    var uris: []Uri = &.{};
    if (url) |u| {
        const uri_copy = try allocator.dupe(u8, u);
        errdefer allocator.free(uri_copy);

        uris = try allocator.alloc(Uri, 1);
        uris[0] = .{ .uri = uri_copy };
    }

    return Item{
        .id = Uuid.generate(),
        .name = name_copy,
        .notes = null,
        .item_type = .login,
        .data = .{
            .login = .{
                .username = username_copy,
                .password = password_copy,
                .uris = uris,
            },
        },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = now,
        .modified_at = now,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}

pub fn createSecureNoteItem(
    allocator: std.mem.Allocator,
    name: []const u8,
    notes: []const u8,
) !Item {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);

    const notes_copy = try allocator.dupe(u8, notes);
    errdefer allocator.free(notes_copy);

    return Item{
        .id = Uuid.generate(),
        .name = name_copy,
        .notes = notes_copy,
        .item_type = .secure_note,
        .data = .{ .secure_note = .{} },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = now,
        .modified_at = now,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}

pub fn createCardItem(
    allocator: std.mem.Allocator,
    name: []const u8,
    cardholder: ?[]const u8,
    number: ?[]const u8,
    exp_month: ?u8,
    exp_year: ?u16,
    cvv: ?[]const u8,
) !Item {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);

    const cardholder_copy = if (cardholder) |c| try allocator.dupe(u8, c) else null;
    errdefer if (cardholder_copy) |c| allocator.free(c);

    const number_copy = if (number) |n| try allocator.dupe(u8, n) else null;
    errdefer if (number_copy) |n| allocator.free(n);

    const cvv_copy = if (cvv) |c| try allocator.dupe(u8, c) else null;
    errdefer if (cvv_copy) |c| allocator.free(c);

    return Item{
        .id = Uuid.generate(),
        .name = name_copy,
        .notes = null,
        .item_type = .card,
        .data = .{
            .card = .{
                .cardholder_name = cardholder_copy,
                .number = number_copy,
                .exp_month = exp_month,
                .exp_year = exp_year,
                .cvv = cvv_copy,
            },
        },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = now,
        .modified_at = now,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}
```

**Step 3: Run tests**

Run: `zig build test 2>&1 | grep -E "(create|PASS|FAIL)"`
Expected: PASS

**Step 4: Commit**

```bash
git add src/core/item.zig
git commit -m "feat(core): add item factory functions for login, secure note, and card"
```

---

## Task 8: Create Serializer V2

**Files:**
- Create: `src/core/serializer_v2.zig`

**Step 1: Create serializer with basic structure**

```zig
const std = @import("std");
const item = @import("item.zig");
const Uuid = @import("uuid.zig").Uuid;

pub const SerializeError = error{
    OutOfMemory,
};

pub const DeserializeError = error{
    InvalidData,
    UnexpectedEndOfData,
    InvalidItemType,
    OutOfMemory,
};

pub fn serializeItems(allocator: std.mem.Allocator, items: []const item.Item) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);

    var writer = buffer.writer(allocator);

    // Write item count
    try writer.writeInt(u32, @intCast(items.len), .little);

    for (items) |i| {
        try serializeItem(allocator, &buffer, i);
    }

    return buffer.toOwnedSlice(allocator);
}

fn serializeItem(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), i: item.Item) !void {
    var writer = buffer.writer(allocator);

    // UUID
    try buffer.appendSlice(allocator, &i.id.bytes);

    // Name and notes
    try writeString(allocator, buffer, i.name);
    try writeOptionalString(allocator, buffer, i.notes);

    // Type
    try writer.writeByte(@intFromEnum(i.item_type));

    // Flags
    try writer.writeByte(if (i.favorite) 1 else 0);

    // Timestamps
    try writer.writeInt(i64, i.created_at, .little);
    try writer.writeInt(i64, i.modified_at, .little);
    try writeOptionalI64(allocator, buffer, i.last_accessed_at);
    try writer.writeInt(u32, i.access_count, .little);
    try writeOptionalI64(allocator, buffer, i.deleted_at);

    // Custom fields
    try writer.writeInt(u32, @intCast(i.fields.len), .little);
    for (i.fields) |f| {
        try serializeCustomField(allocator, buffer, f);
    }

    // Password history
    try writer.writeInt(u32, @intCast(i.password_history.len), .little);
    for (i.password_history) |h| {
        try writeString(allocator, buffer, h.password);
        try writer.writeInt(i64, h.changed_at, .little);
    }

    // Type-specific data
    try serializeItemData(allocator, buffer, i.data);
}

fn serializeCustomField(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), f: item.CustomField) !void {
    var writer = buffer.writer(allocator);
    try writeString(allocator, buffer, f.name);
    try writeOptionalString(allocator, buffer, f.value);
    try writer.writeByte(@intFromEnum(f.field_type));
}

fn serializeItemData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), data: item.ItemData) !void {
    switch (data) {
        .login => |l| try serializeLoginData(allocator, buffer, l),
        .secure_note => {},
        .card => |c| try serializeCardData(allocator, buffer, c),
        .identity => |i| try serializeIdentityData(allocator, buffer, i),
        .ssh_key => |s| try serializeSshKeyData(allocator, buffer, s),
        .api_credential => |a| try serializeApiCredentialData(allocator, buffer, a),
        .database => |d| try serializeDatabaseData(allocator, buffer, d),
        .wifi => |w| try serializeWifiData(allocator, buffer, w),
        .license => |l| try serializeLicenseData(allocator, buffer, l),
    }
}

fn serializeLoginData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), l: item.LoginData) !void {
    var writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, l.username);
    try writeOptionalString(allocator, buffer, l.password);

    // URIs
    try writer.writeInt(u32, @intCast(l.uris.len), .little);
    for (l.uris) |uri| {
        try writeString(allocator, buffer, uri.uri);
        try writer.writeByte(@intFromEnum(uri.match_type));
    }

    // TOTP
    if (l.totp) |t| {
        try writer.writeByte(1);
        try writeString(allocator, buffer, t.secret);
        try writer.writeByte(@intFromEnum(t.algorithm));
        try writer.writeByte(t.digits);
        try writer.writeInt(u32, t.period, .little);
    } else {
        try writer.writeByte(0);
    }

    // Passkeys
    try writer.writeInt(u32, @intCast(l.passkeys.len), .little);
    for (l.passkeys) |pk| {
        try writeString(allocator, buffer, pk.credential_id);
        try writeString(allocator, buffer, pk.private_key);
        try writeString(allocator, buffer, pk.public_key);
        try writer.writeInt(i32, @intFromEnum(pk.algorithm), .little);
        try writeString(allocator, buffer, pk.rp_id);
        try writeOptionalString(allocator, buffer, pk.rp_name);
        try writeString(allocator, buffer, pk.user_handle);
        try writeOptionalString(allocator, buffer, pk.user_name);
        try writer.writeInt(u32, pk.counter, .little);
    }
}

fn serializeCardData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), c: item.CardData) !void {
    var writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, c.cardholder_name);
    try writeOptionalString(allocator, buffer, c.number);
    try writer.writeByte(if (c.brand) |b| @intFromEnum(b) else 0);
    try writer.writeByte(c.exp_month orelse 0);
    try writer.writeInt(u16, c.exp_year orelse 0, .little);
    try writeOptionalString(allocator, buffer, c.cvv);
    try writeOptionalString(allocator, buffer, c.pin);
}

fn serializeIdentityData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), i: item.IdentityData) !void {
    var writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, i.title);
    try writeOptionalString(allocator, buffer, i.first_name);
    try writeOptionalString(allocator, buffer, i.middle_name);
    try writeOptionalString(allocator, buffer, i.last_name);
    try writeOptionalString(allocator, buffer, i.email);
    try writeOptionalString(allocator, buffer, i.phone);

    // Address
    if (i.address) |a| {
        try writer.writeByte(1);
        try writeOptionalString(allocator, buffer, a.street1);
        try writeOptionalString(allocator, buffer, a.street2);
        try writeOptionalString(allocator, buffer, a.city);
        try writeOptionalString(allocator, buffer, a.state);
        try writeOptionalString(allocator, buffer, a.postal_code);
        try writeOptionalString(allocator, buffer, a.country);
    } else {
        try writer.writeByte(0);
    }

    try writeOptionalString(allocator, buffer, i.ssn);
    try writeOptionalString(allocator, buffer, i.passport);
    try writeOptionalString(allocator, buffer, i.license_number);
    try writeOptionalString(allocator, buffer, i.company);
    try writeOptionalString(allocator, buffer, i.job_title);
}

fn serializeSshKeyData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: item.SshKeyData) !void {
    var writer = buffer.writer(allocator);

    try writeString(allocator, buffer, s.private_key);
    try writeString(allocator, buffer, s.public_key);
    try writeString(allocator, buffer, s.fingerprint);
    try writer.writeByte(@intFromEnum(s.key_type));
    try writeOptionalString(allocator, buffer, s.passphrase);
}

fn serializeApiCredentialData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), a: item.ApiCredentialData) !void {
    try writeOptionalString(allocator, buffer, a.api_key);
    try writeOptionalString(allocator, buffer, a.api_secret);
    try writeOptionalString(allocator, buffer, a.endpoint);
    try writeOptionalString(allocator, buffer, a.documentation_url);
}

fn serializeDatabaseData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), d: item.DatabaseData) !void {
    var writer = buffer.writer(allocator);

    try writer.writeByte(@intFromEnum(d.db_type));
    try writeOptionalString(allocator, buffer, d.host);
    try writer.writeInt(u16, d.port orelse 0, .little);
    try writeOptionalString(allocator, buffer, d.database);
    try writeOptionalString(allocator, buffer, d.username);
    try writeOptionalString(allocator, buffer, d.password);
    try writeOptionalString(allocator, buffer, d.connection_string);
    try writeOptionalString(allocator, buffer, d.sid);
}

fn serializeWifiData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), w: item.WifiData) !void {
    var writer = buffer.writer(allocator);

    try writeString(allocator, buffer, w.ssid);
    try writeOptionalString(allocator, buffer, w.password);
    try writer.writeByte(@intFromEnum(w.security));
    try writer.writeByte(if (w.hidden) 1 else 0);
}

fn serializeLicenseData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), l: item.LicenseData) !void {
    try writeOptionalString(allocator, buffer, l.license_key);
    try writeOptionalString(allocator, buffer, l.product_name);
    try writeOptionalString(allocator, buffer, l.version);
    try writeOptionalString(allocator, buffer, l.publisher);
    try writeOptionalString(allocator, buffer, l.email);
    try writeOptionalI64(allocator, buffer, l.purchase_date);
    try writeOptionalI64(allocator, buffer, l.expiration_date);
}

fn writeString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: []const u8) !void {
    var writer = buffer.writer(allocator);
    try writer.writeInt(u32, @intCast(s.len), .little);
    try buffer.appendSlice(allocator, s);
}

fn writeOptionalString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: ?[]const u8) !void {
    var writer = buffer.writer(allocator);
    if (s) |str| {
        try writer.writeByte(1);
        try writeString(allocator, buffer, str);
    } else {
        try writer.writeByte(0);
    }
}

fn writeOptionalI64(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), v: ?i64) !void {
    var writer = buffer.writer(allocator);
    if (v) |val| {
        try writer.writeByte(1);
        try writer.writeInt(i64, val, .little);
    } else {
        try writer.writeByte(0);
    }
}

// Deserialization functions will be added in next task

test "serialize empty items" {
    const allocator = std.testing.allocator;
    var items: [0]item.Item = .{};

    const serialized = try serializeItems(allocator, &items);
    defer allocator.free(serialized);

    try std.testing.expectEqual(@as(usize, 4), serialized.len); // Just the count
}
```

**Step 2: Run test**

Run: `zig build test 2>&1 | grep -E "(serialize|PASS|FAIL)"`
Expected: PASS

**Step 3: Commit**

```bash
git add src/core/serializer_v2.zig
git commit -m "feat(core): add serializer v2 with serialize functions for all item types"
```

---

## Task 9: Add Deserializer V2

**Files:**
- Modify: `src/core/serializer_v2.zig`

**Step 1: Add deserialization functions**

Add to `serializer_v2.zig`:

```zig
pub fn deserializeItems(allocator: std.mem.Allocator, data: []const u8) ![]item.Item {
    var stream = std.io.fixedBufferStream(data);
    var reader = stream.reader();

    const count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    var items: std.ArrayList(item.Item) = .empty;
    errdefer {
        for (items.items) |*i| i.deinit(allocator);
        items.deinit(allocator);
    }

    for (0..count) |_| {
        const i = try deserializeItem(allocator, &reader);
        try items.append(allocator, i);
    }

    return items.toOwnedSlice(allocator);
}

fn deserializeItem(allocator: std.mem.Allocator, reader: anytype) !item.Item {
    // UUID
    var uuid_bytes: [16]u8 = undefined;
    _ = reader.readAll(&uuid_bytes) catch return DeserializeError.UnexpectedEndOfData;
    const id = Uuid.fromBytes(uuid_bytes);

    // Name and notes
    const name = try readString(allocator, reader);
    errdefer allocator.free(name);

    const notes = try readOptionalString(allocator, reader);
    errdefer if (notes) |n| allocator.free(n);

    // Type
    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const item_type = std.meta.intToEnum(item.ItemType, type_byte) catch return DeserializeError.InvalidItemType;

    // Flags
    const favorite_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const favorite = favorite_byte == 1;

    // Timestamps
    const created_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    const modified_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    const last_accessed_at = try readOptionalI64(reader);
    const access_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    const deleted_at = try readOptionalI64(reader);

    // Custom fields
    const fields_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var fields = try allocator.alloc(item.CustomField, fields_count);
    errdefer allocator.free(fields);

    for (0..fields_count) |i| {
        fields[i] = try deserializeCustomField(allocator, reader);
    }

    // Password history
    const history_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var history = try allocator.alloc(item.PasswordHistoryEntry, history_count);
    errdefer allocator.free(history);

    for (0..history_count) |i| {
        const pw = try readString(allocator, reader);
        const changed_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
        history[i] = .{ .password = pw, .changed_at = changed_at };
    }

    // Type-specific data
    const data = try deserializeItemData(allocator, reader, item_type);

    return item.Item{
        .id = id,
        .name = name,
        .notes = notes,
        .item_type = item_type,
        .data = data,
        .favorite = favorite,
        .fields = fields,
        .password_history = history,
        .created_at = created_at,
        .modified_at = modified_at,
        .last_accessed_at = last_accessed_at,
        .access_count = access_count,
        .deleted_at = deleted_at,
    };
}

fn deserializeCustomField(allocator: std.mem.Allocator, reader: anytype) !item.CustomField {
    const name = try readString(allocator, reader);
    errdefer allocator.free(name);

    const value = try readOptionalString(allocator, reader);
    errdefer if (value) |v| allocator.free(v);

    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const field_type = std.meta.intToEnum(item.FieldType, type_byte) catch return DeserializeError.InvalidData;

    return .{
        .name = name,
        .value = value,
        .field_type = field_type,
    };
}

fn deserializeItemData(allocator: std.mem.Allocator, reader: anytype, item_type: item.ItemType) !item.ItemData {
    return switch (item_type) {
        .login => .{ .login = try deserializeLoginData(allocator, reader) },
        .secure_note => .{ .secure_note = .{} },
        .card => .{ .card = try deserializeCardData(allocator, reader) },
        .identity => .{ .identity = try deserializeIdentityData(allocator, reader) },
        .ssh_key => .{ .ssh_key = try deserializeSshKeyData(allocator, reader) },
        .api_credential => .{ .api_credential = try deserializeApiCredentialData(allocator, reader) },
        .database => .{ .database = try deserializeDatabaseData(allocator, reader) },
        .wifi => .{ .wifi = try deserializeWifiData(allocator, reader) },
        .license => .{ .license = try deserializeLicenseData(allocator, reader) },
    };
}

fn deserializeLoginData(allocator: std.mem.Allocator, reader: anytype) !item.LoginData {
    const username = try readOptionalString(allocator, reader);
    errdefer if (username) |u| allocator.free(u);

    const password = try readOptionalString(allocator, reader);
    errdefer if (password) |p| allocator.free(p);

    // URIs
    const uri_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var uris = try allocator.alloc(item.Uri, uri_count);
    errdefer allocator.free(uris);

    for (0..uri_count) |i| {
        const uri_str = try readString(allocator, reader);
        const match_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const match_type = std.meta.intToEnum(item.UriMatchType, match_byte) catch return DeserializeError.InvalidData;
        uris[i] = .{ .uri = uri_str, .match_type = match_type };
    }

    // TOTP
    const has_totp = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    var totp: ?item.TotpData = null;
    if (has_totp == 1) {
        const secret = try readString(allocator, reader);
        const algo_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const algorithm = std.meta.intToEnum(item.TotpAlgorithm, algo_byte) catch return DeserializeError.InvalidData;
        const digits = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const period = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
        totp = .{
            .secret = secret,
            .algorithm = algorithm,
            .digits = digits,
            .period = period,
        };
    }

    // Passkeys
    const pk_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var passkeys = try allocator.alloc(item.PasskeyData, pk_count);
    errdefer allocator.free(passkeys);

    for (0..pk_count) |i| {
        passkeys[i] = try deserializePasskeyData(allocator, reader);
    }

    return .{
        .username = username,
        .password = password,
        .uris = uris,
        .totp = totp,
        .passkeys = passkeys,
    };
}

fn deserializePasskeyData(allocator: std.mem.Allocator, reader: anytype) !item.PasskeyData {
    const credential_id = try readString(allocator, reader);
    const private_key = try readString(allocator, reader);
    const public_key = try readString(allocator, reader);
    const algo_int = reader.readInt(i32, .little) catch return DeserializeError.UnexpectedEndOfData;
    const algorithm = std.meta.intToEnum(item.PasskeyAlgorithm, algo_int) catch return DeserializeError.InvalidData;
    const rp_id = try readString(allocator, reader);
    const rp_name = try readOptionalString(allocator, reader);
    const user_handle = try readString(allocator, reader);
    const user_name = try readOptionalString(allocator, reader);
    const counter = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    return .{
        .credential_id = credential_id,
        .private_key = private_key,
        .public_key = public_key,
        .algorithm = algorithm,
        .rp_id = rp_id,
        .rp_name = rp_name,
        .user_handle = user_handle,
        .user_name = user_name,
        .counter = counter,
    };
}

fn deserializeCardData(allocator: std.mem.Allocator, reader: anytype) !item.CardData {
    const cardholder = try readOptionalString(allocator, reader);
    const number = try readOptionalString(allocator, reader);
    const brand_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const brand: ?item.CardBrand = if (brand_byte == 0) null else std.meta.intToEnum(item.CardBrand, brand_byte) catch null;
    const exp_month_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const exp_month: ?u8 = if (exp_month_byte == 0) null else exp_month_byte;
    const exp_year_val = reader.readInt(u16, .little) catch return DeserializeError.UnexpectedEndOfData;
    const exp_year: ?u16 = if (exp_year_val == 0) null else exp_year_val;
    const cvv = try readOptionalString(allocator, reader);
    const pin = try readOptionalString(allocator, reader);

    return .{
        .cardholder_name = cardholder,
        .number = number,
        .brand = brand,
        .exp_month = exp_month,
        .exp_year = exp_year,
        .cvv = cvv,
        .pin = pin,
    };
}

fn deserializeIdentityData(allocator: std.mem.Allocator, reader: anytype) !item.IdentityData {
    const title = try readOptionalString(allocator, reader);
    const first_name = try readOptionalString(allocator, reader);
    const middle_name = try readOptionalString(allocator, reader);
    const last_name = try readOptionalString(allocator, reader);
    const email = try readOptionalString(allocator, reader);
    const phone = try readOptionalString(allocator, reader);

    const has_address = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    var address: ?item.AddressData = null;
    if (has_address == 1) {
        address = .{
            .street1 = try readOptionalString(allocator, reader),
            .street2 = try readOptionalString(allocator, reader),
            .city = try readOptionalString(allocator, reader),
            .state = try readOptionalString(allocator, reader),
            .postal_code = try readOptionalString(allocator, reader),
            .country = try readOptionalString(allocator, reader),
        };
    }

    const ssn = try readOptionalString(allocator, reader);
    const passport = try readOptionalString(allocator, reader);
    const license_number = try readOptionalString(allocator, reader);
    const company = try readOptionalString(allocator, reader);
    const job_title = try readOptionalString(allocator, reader);

    return .{
        .title = title,
        .first_name = first_name,
        .middle_name = middle_name,
        .last_name = last_name,
        .email = email,
        .phone = phone,
        .address = address,
        .ssn = ssn,
        .passport = passport,
        .license_number = license_number,
        .company = company,
        .job_title = job_title,
    };
}

fn deserializeSshKeyData(allocator: std.mem.Allocator, reader: anytype) !item.SshKeyData {
    const private_key = try readString(allocator, reader);
    const public_key = try readString(allocator, reader);
    const fingerprint = try readString(allocator, reader);
    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const key_type = std.meta.intToEnum(item.SshKeyType, type_byte) catch return DeserializeError.InvalidData;
    const passphrase = try readOptionalString(allocator, reader);

    return .{
        .private_key = private_key,
        .public_key = public_key,
        .fingerprint = fingerprint,
        .key_type = key_type,
        .passphrase = passphrase,
    };
}

fn deserializeApiCredentialData(allocator: std.mem.Allocator, reader: anytype) !item.ApiCredentialData {
    return .{
        .api_key = try readOptionalString(allocator, reader),
        .api_secret = try readOptionalString(allocator, reader),
        .endpoint = try readOptionalString(allocator, reader),
        .documentation_url = try readOptionalString(allocator, reader),
    };
}

fn deserializeDatabaseData(allocator: std.mem.Allocator, reader: anytype) !item.DatabaseData {
    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const db_type = std.meta.intToEnum(item.DatabaseType, type_byte) catch return DeserializeError.InvalidData;
    const host = try readOptionalString(allocator, reader);
    const port_val = reader.readInt(u16, .little) catch return DeserializeError.UnexpectedEndOfData;
    const port: ?u16 = if (port_val == 0) null else port_val;
    const database = try readOptionalString(allocator, reader);
    const username = try readOptionalString(allocator, reader);
    const password = try readOptionalString(allocator, reader);
    const connection_string = try readOptionalString(allocator, reader);
    const sid = try readOptionalString(allocator, reader);

    return .{
        .db_type = db_type,
        .host = host,
        .port = port,
        .database = database,
        .username = username,
        .password = password,
        .connection_string = connection_string,
        .sid = sid,
    };
}

fn deserializeWifiData(allocator: std.mem.Allocator, reader: anytype) !item.WifiData {
    const ssid = try readString(allocator, reader);
    const password = try readOptionalString(allocator, reader);
    const sec_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const security = std.meta.intToEnum(item.WifiSecurity, sec_byte) catch return DeserializeError.InvalidData;
    const hidden_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;

    return .{
        .ssid = ssid,
        .password = password,
        .security = security,
        .hidden = hidden_byte == 1,
    };
}

fn deserializeLicenseData(allocator: std.mem.Allocator, reader: anytype) !item.LicenseData {
    return .{
        .license_key = try readOptionalString(allocator, reader),
        .product_name = try readOptionalString(allocator, reader),
        .version = try readOptionalString(allocator, reader),
        .publisher = try readOptionalString(allocator, reader),
        .email = try readOptionalString(allocator, reader),
        .purchase_date = try readOptionalI64(reader),
        .expiration_date = try readOptionalI64(reader),
    };
}

fn readString(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    const len = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    if (len > 1024 * 1024) return DeserializeError.InvalidData;

    const str = try allocator.alloc(u8, len);
    errdefer allocator.free(str);

    const bytes_read = reader.readAll(str) catch return DeserializeError.UnexpectedEndOfData;
    if (bytes_read != len) return DeserializeError.UnexpectedEndOfData;

    return str;
}

fn readOptionalString(allocator: std.mem.Allocator, reader: anytype) !?[]u8 {
    const present = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    if (present == 1) {
        return try readString(allocator, reader);
    }
    return null;
}

fn readOptionalI64(reader: anytype) !?i64 {
    const present = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    if (present == 1) {
        return reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    }
    return null;
}

test "serialize and deserialize login item roundtrip" {
    const allocator = std.testing.allocator;

    var login_item = try item.createLoginItem(allocator, "github.com", "testuser", "secretpass", "https://github.com");
    defer login_item.deinit(allocator);

    var items_arr = [_]item.Item{login_item};
    // Don't defer deinit on items_arr since login_item handles it

    const serialized = try serializeItems(allocator, &items_arr);
    defer allocator.free(serialized);

    // Need to make a copy since we'll deserialize into new memory
    var items_for_serialize = [_]item.Item{login_item};
    _ = &items_for_serialize;

    // Actually test deserialization
    const deserialized = try deserializeItems(allocator, serialized);
    defer {
        for (deserialized) |*i| i.deinit(allocator);
        allocator.free(deserialized);
    }

    try std.testing.expectEqual(@as(usize, 1), deserialized.len);
    try std.testing.expectEqualStrings("github.com", deserialized[0].name);
    try std.testing.expectEqual(item.ItemType.login, deserialized[0].item_type);
    try std.testing.expectEqualStrings("testuser", deserialized[0].data.login.username.?);
}
```

**Step 2: Run test**

Run: `zig build test 2>&1 | grep -E "(roundtrip|PASS|FAIL)"`
Expected: PASS

**Step 3: Commit**

```bash
git add src/core/serializer_v2.zig
git commit -m "feat(core): add deserializer v2 with roundtrip test"
```

---

## Task 10: Update Vault Header for V2

**Files:**
- Modify: `src/core/vault.zig`

**Step 1: Update VAULT_VERSION constant**

Change line 23 in vault.zig:
```zig
pub const VAULT_VERSION: u16 = 2;
```

**Step 2: Add version check that allows both 1 and 2**

In `VaultHeader.deserialize`, update the version check:
```zig
if (version != 1 and version != 2) {
    return VaultError.UnsupportedVersion;
}
```

**Step 3: Run existing tests**

Run: `zig build test`
Expected: All existing tests pass

**Step 4: Commit**

```bash
git add src/core/vault.zig
git commit -m "feat(core): bump vault version to 2, allow reading v1 and v2"
```

---

## Task 11: Add Migration from V1 to V2

**Files:**
- Create: `src/core/migration.zig`

**Step 1: Create migration module**

```zig
const std = @import("std");
const item = @import("item.zig");
const entry = @import("entry.zig");
const Uuid = @import("uuid.zig").Uuid;

pub fn migrateEntryToItem(allocator: std.mem.Allocator, e: entry.Entry) !item.Item {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, e.name);
    errdefer allocator.free(name_copy);

    switch (e.data) {
        .password => |p| {
            return try migratePasswordEntry(allocator, name_copy, e.created_at, e.modified_at, p);
        },
        .totp => |t| {
            return try migrateTotpEntry(allocator, name_copy, e.created_at, e.modified_at, t);
        },
        .passkey => |pk| {
            return try migratePasskeyEntry(allocator, name_copy, e.created_at, e.modified_at, pk);
        },
    }
    _ = now;
}

fn migratePasswordEntry(
    allocator: std.mem.Allocator,
    name: []const u8,
    created_at: i64,
    modified_at: i64,
    p: entry.PasswordEntry,
) !item.Item {
    const username_copy = if (p.username) |u| try allocator.dupe(u8, u) else null;
    errdefer if (username_copy) |u| allocator.free(u);

    const password_copy = try allocator.dupe(u8, p.password);
    errdefer allocator.free(password_copy);

    const notes_copy = if (p.notes) |n| try allocator.dupe(u8, n) else null;
    errdefer if (notes_copy) |n| allocator.free(n);

    // URIs
    var uris: []item.Uri = &.{};
    if (p.url) |url| {
        const uri_copy = try allocator.dupe(u8, url);
        errdefer allocator.free(uri_copy);

        uris = try allocator.alloc(item.Uri, 1);
        uris[0] = .{ .uri = uri_copy };
    }

    // TOTP
    var totp: ?item.TotpData = null;
    if (p.totp_secret) |secret| {
        const secret_copy = try allocator.dupe(u8, secret);
        totp = .{
            .secret = secret_copy,
            .algorithm = switch (p.totp_algorithm) {
                .sha1 => .sha1,
                .sha256 => .sha256,
                .sha512 => .sha512,
            },
            .digits = p.totp_digits,
            .period = p.totp_period,
        };
    }

    return item.Item{
        .id = Uuid.generate(),
        .name = name,
        .notes = notes_copy,
        .item_type = .login,
        .data = .{
            .login = .{
                .username = username_copy,
                .password = password_copy,
                .uris = uris,
                .totp = totp,
                .passkeys = &.{},
            },
        },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = created_at,
        .modified_at = modified_at,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}

fn migrateTotpEntry(
    allocator: std.mem.Allocator,
    name: []const u8,
    created_at: i64,
    modified_at: i64,
    t: entry.TotpEntry,
) !item.Item {
    const secret_copy = try allocator.dupe(u8, t.secret);
    errdefer allocator.free(secret_copy);

    const issuer_notes = if (t.issuer) |i| try allocator.dupe(u8, i) else null;

    return item.Item{
        .id = Uuid.generate(),
        .name = name,
        .notes = issuer_notes,
        .item_type = .login,
        .data = .{
            .login = .{
                .username = null,
                .password = null,
                .uris = &.{},
                .totp = .{
                    .secret = secret_copy,
                    .algorithm = switch (t.algorithm) {
                        .sha1 => .sha1,
                        .sha256 => .sha256,
                        .sha512 => .sha512,
                    },
                    .digits = t.digits,
                    .period = t.period,
                },
                .passkeys = &.{},
            },
        },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = created_at,
        .modified_at = modified_at,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}

fn migratePasskeyEntry(
    allocator: std.mem.Allocator,
    name: []const u8,
    created_at: i64,
    modified_at: i64,
    pk: entry.PasskeyEntry,
) !item.Item {
    const cred_copy = try allocator.dupe(u8, pk.credential_id);
    errdefer allocator.free(cred_copy);

    const priv_copy = try allocator.dupe(u8, pk.private_key);
    errdefer allocator.free(priv_copy);

    const pub_copy = try allocator.dupe(u8, pk.public_key);
    errdefer allocator.free(pub_copy);

    const rp_id_copy = try allocator.dupe(u8, pk.rp_id);
    errdefer allocator.free(rp_id_copy);

    const rp_name_copy = if (pk.rp_name) |n| try allocator.dupe(u8, n) else null;
    errdefer if (rp_name_copy) |n| allocator.free(n);

    const user_handle_copy = try allocator.dupe(u8, pk.user_handle);
    errdefer allocator.free(user_handle_copy);

    const user_name_copy = if (pk.user_name) |n| try allocator.dupe(u8, n) else null;
    errdefer if (user_name_copy) |n| allocator.free(n);

    var passkeys = try allocator.alloc(item.PasskeyData, 1);
    passkeys[0] = .{
        .credential_id = cred_copy,
        .private_key = priv_copy,
        .public_key = pub_copy,
        .algorithm = switch (pk.algorithm) {
            .es256 => .es256,
            .ed25519 => .ed25519,
            .rs256 => .rs256,
        },
        .rp_id = rp_id_copy,
        .rp_name = rp_name_copy,
        .user_handle = user_handle_copy,
        .user_name = user_name_copy,
        .counter = pk.counter,
    };

    // Use rp_id as URI
    const uri_copy = try allocator.dupe(u8, pk.rp_id);
    var uris = try allocator.alloc(item.Uri, 1);
    uris[0] = .{ .uri = uri_copy };

    return item.Item{
        .id = Uuid.generate(),
        .name = name,
        .notes = null,
        .item_type = .login,
        .data = .{
            .login = .{
                .username = user_name_copy,
                .password = null,
                .uris = uris,
                .totp = null,
                .passkeys = passkeys,
            },
        },
        .favorite = false,
        .fields = &.{},
        .password_history = &.{},
        .created_at = created_at,
        .modified_at = modified_at,
        .last_accessed_at = null,
        .access_count = 0,
        .deleted_at = null,
    };
}

pub fn migrateAllEntries(allocator: std.mem.Allocator, entries: []const entry.Entry) ![]item.Item {
    var items: std.ArrayList(item.Item) = .empty;
    errdefer {
        for (items.items) |*i| i.deinit(allocator);
        items.deinit(allocator);
    }

    for (entries) |e| {
        const migrated = try migrateEntryToItem(allocator, e);
        try items.append(allocator, migrated);
    }

    return items.toOwnedSlice(allocator);
}

test "migrate password entry to login item" {
    const allocator = std.testing.allocator;

    const e = try entry.createPasswordEntry(allocator, "test.com", "user", "pass", "https://test.com");
    var mutable_entry = e;
    defer mutable_entry.deinit(allocator);

    var migrated = try migrateEntryToItem(allocator, e);
    defer migrated.deinit(allocator);

    try std.testing.expectEqual(item.ItemType.login, migrated.item_type);
    try std.testing.expectEqualStrings("test.com", migrated.name);
    try std.testing.expectEqualStrings("user", migrated.data.login.username.?);
    try std.testing.expectEqualStrings("pass", migrated.data.login.password.?);
    try std.testing.expectEqual(@as(usize, 1), migrated.data.login.uris.len);
}
```

**Step 2: Run test**

Run: `zig build test 2>&1 | grep -E "(migrate|PASS|FAIL)"`
Expected: PASS

**Step 3: Commit**

```bash
git add src/core/migration.zig
git commit -m "feat(core): add migration module for v1 entries to v2 items"
```

---

## Summary

After completing all 11 tasks, Phase 1 delivers:

1. **UUID type** for unique item identification
2. **Item struct** with all 9 item types
3. **Full data structures** for Login, Card, Identity, SSH Key, API Credential, Database, WiFi, License
4. **Custom fields** with typed values
5. **Password history** entries
6. **Serializer V2** for the new format
7. **Migration** from V1 entries to V2 items
8. **Vault header** updated to version 2

Next phase will add folders, tags, and quick access features.
