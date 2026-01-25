const std = @import("std");

pub const EntryType = enum(u8) {
    password = 1,
    totp = 2,
    passkey = 3,
};

pub const Entry = struct {
    name: []const u8,
    entry_type: EntryType,
    created_at: i64,
    modified_at: i64,
    data: EntryData,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);

        switch (self.data) {
            .password => |*p| p.deinit(allocator),
            .totp => |*t| t.deinit(allocator),
            .passkey => |*pk| pk.deinit(allocator),
        }
    }
};

pub const EntryData = union(EntryType) {
    password: PasswordEntry,
    totp: TotpEntry,
    passkey: PasskeyEntry,
};

pub const PasswordEntry = struct {
    username: ?[]const u8,
    password: []const u8,
    url: ?[]const u8,
    notes: ?[]const u8,
    totp_secret: ?[]const u8 = null,
    totp_algorithm: TotpAlgorithm = .sha1,
    totp_digits: u8 = 6,
    totp_period: u32 = 30,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.username) |u| allocator.free(u);
        @memset(@constCast(self.password), 0);
        allocator.free(self.password);
        if (self.url) |url| allocator.free(url);
        if (self.notes) |n| allocator.free(n);
        if (self.totp_secret) |secret| {
            @memset(@constCast(secret), 0);
            allocator.free(secret);
        }
    }

    pub fn hasTotp(self: *const Self) bool {
        return self.totp_secret != null;
    }
};

pub const TotpEntry = struct {
    secret: []const u8,
    algorithm: TotpAlgorithm = .sha1,
    digits: u8 = 6,
    period: u32 = 30,
    issuer: ?[]const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        @memset(@constCast(self.secret), 0);
        allocator.free(self.secret);
        if (self.issuer) |i| allocator.free(i);
    }
};

pub const TotpAlgorithm = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    sha512 = 3,
};

pub const PasskeyEntry = struct {
    credential_id: []const u8,
    private_key: []const u8,
    public_key: []const u8,
    algorithm: PasskeyAlgorithm,
    rp_id: []const u8,
    rp_name: ?[]const u8,
    user_handle: []const u8,
    user_name: ?[]const u8,
    counter: u32,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
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

pub const PasskeyAlgorithm = enum(i32) {
    es256 = -7,
    ed25519 = -8,
    rs256 = -257,
};

pub fn createPasswordEntry(
    allocator: std.mem.Allocator,
    name: []const u8,
    username: ?[]const u8,
    password: []const u8,
    url: ?[]const u8,
) !Entry {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);

    const username_copy = if (username) |u| try allocator.dupe(u8, u) else null;
    errdefer if (username_copy) |u| allocator.free(u);

    const password_copy = try allocator.dupe(u8, password);
    errdefer allocator.free(password_copy);

    const url_copy = if (url) |u| try allocator.dupe(u8, u) else null;
    errdefer if (url_copy) |u| allocator.free(u);

    return Entry{
        .name = name_copy,
        .entry_type = .password,
        .created_at = now,
        .modified_at = now,
        .data = .{
            .password = .{
                .username = username_copy,
                .password = password_copy,
                .url = url_copy,
                .notes = null,
            },
        },
    };
}

pub fn createTotpEntry(
    allocator: std.mem.Allocator,
    name: []const u8,
    secret: []const u8,
    issuer: ?[]const u8,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
) !Entry {
    const now = std.time.timestamp();

    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);

    const secret_copy = try allocator.dupe(u8, secret);
    errdefer allocator.free(secret_copy);

    const issuer_copy = if (issuer) |i| try allocator.dupe(u8, i) else null;
    errdefer if (issuer_copy) |i| allocator.free(i);

    return Entry{
        .name = name_copy,
        .entry_type = .totp,
        .created_at = now,
        .modified_at = now,
        .data = .{
            .totp = .{
                .secret = secret_copy,
                .algorithm = algorithm,
                .digits = digits,
                .period = period,
                .issuer = issuer_copy,
            },
        },
    };
}

test "create password entry" {
    const allocator = std.testing.allocator;

    var e = try createPasswordEntry(
        allocator,
        "github.com",
        "testuser",
        "secretpassword",
        "https://github.com",
    );
    defer e.deinit(allocator);

    try std.testing.expectEqualStrings("github.com", e.name);
    try std.testing.expectEqual(EntryType.password, e.entry_type);

    const pwd = e.data.password;
    try std.testing.expectEqualStrings("testuser", pwd.username.?);
    try std.testing.expectEqualStrings("secretpassword", pwd.password);
}
