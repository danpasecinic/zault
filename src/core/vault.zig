const std = @import("std");
const entry = @import("entry.zig");

pub const VaultError = error{
    VaultNotFound,
    VaultLocked,
    VaultCorrupted,
    InvalidMasterPassword,
    EntryNotFound,
    EntryAlreadyExists,
    IoError,
    CryptoError,
};

pub const VaultHeader = struct {
    magic: [4]u8 = .{ 'Z', 'A', 'U', 'L' },
    version: u16 = 1,
    kdf_algorithm: u8 = 1,
    encryption_algorithm: u8 = 1,
    kdf_memory: u32 = 65536,
    kdf_iterations: u32 = 3,
    kdf_parallelism: u8 = 4,
    salt: [32]u8,
    nonce: [24]u8,
    reserved: [16]u8 = [_]u8{0} ** 16,
};

pub const Vault = struct {
    allocator: std.mem.Allocator,
    header: VaultHeader,
    entries: std.ArrayList(entry.Entry),
    is_locked: bool,
    path: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8) Self {
        return Self{
            .allocator = allocator,
            .header = VaultHeader{
                .salt = undefined,
                .nonce = undefined,
            },
            .entries = std.ArrayList(entry.Entry).init(allocator),
            .is_locked = true,
            .path = path,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |*e| {
            e.deinit(self.allocator);
        }
        self.entries.deinit();
    }

    pub fn create(allocator: std.mem.Allocator, path: []const u8, master_password: []const u8) !Self {
        _ = master_password;

        var vault = Self.init(allocator, path);

        std.crypto.random.bytes(&vault.header.salt);
        std.crypto.random.bytes(&vault.header.nonce);

        vault.is_locked = false;

        return vault;
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) !Self {
        _ = allocator;
        _ = path;
        return VaultError.VaultNotFound;
    }

    pub fn unlock(self: *Self, master_password: []const u8) !void {
        _ = master_password;
        self.is_locked = false;
    }

    pub fn lock(self: *Self) void {
        for (self.entries.items) |*e| {
            e.deinit(self.allocator);
        }
        self.entries.clearRetainingCapacity();
        self.is_locked = true;
    }

    pub fn save(self: *Self) !void {
        if (self.is_locked) {
            return VaultError.VaultLocked;
        }
    }

    pub fn addEntry(self: *Self, new_entry: entry.Entry) !void {
        if (self.is_locked) {
            return VaultError.VaultLocked;
        }

        for (self.entries.items) |e| {
            if (std.mem.eql(u8, e.name, new_entry.name)) {
                return VaultError.EntryAlreadyExists;
            }
        }

        try self.entries.append(new_entry);
    }

    pub fn getEntry(self: *Self, name: []const u8) ?*entry.Entry {
        if (self.is_locked) {
            return null;
        }

        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) {
                return e;
            }
        }

        return null;
    }

    pub fn deleteEntry(self: *Self, name: []const u8) !void {
        if (self.is_locked) {
            return VaultError.VaultLocked;
        }

        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, e.name, name)) {
                _ = self.entries.orderedRemove(i);
                return;
            }
        }

        return VaultError.EntryNotFound;
    }
};

pub fn getDefaultVaultPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
    const config_home = std.posix.getenv("XDG_CONFIG_HOME");

    if (config_home) |config| {
        return std.fmt.allocPrint(allocator, "{s}/zault/vault.zault", .{config});
    } else {
        return std.fmt.allocPrint(allocator, "{s}/.config/zault/vault.zault", .{home});
    }
}

test "vault init" {
    const allocator = std.testing.allocator;
    var vault = Vault.init(allocator, "/tmp/test.zault");
    defer vault.deinit();

    try std.testing.expect(vault.is_locked);
    try std.testing.expectEqual(@as(usize, 0), vault.entries.items.len);
}
