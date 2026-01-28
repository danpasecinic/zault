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
