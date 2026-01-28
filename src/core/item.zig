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
        if (self.fields.len > 0) allocator.free(self.fields);

        for (self.password_history) |*h| h.deinit(allocator);
        if (self.password_history.len > 0) allocator.free(self.password_history);

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
            var totp = t.*;
            totp.deinit(allocator);
        }
        for (self.passkeys) |*pk| pk.deinit(allocator);
        if (self.passkeys.len > 0) allocator.free(self.passkeys);
    }

    pub fn hasTotp(self: *const LoginData) bool {
        return self.totp != null;
    }
};

pub const SecureNoteData = struct {};

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
            var addr = a.*;
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
}

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

test "identity data full name" {
    const identity = IdentityData{
        .first_name = "John",
        .middle_name = "Q",
        .last_name = "Public",
    };

    const full = try identity.fullName(std.testing.allocator);
    defer std.testing.allocator.free(full);
    try std.testing.expectEqualStrings("John Q Public", full);
}
