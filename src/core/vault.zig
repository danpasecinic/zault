const std = @import("std");
const entry = @import("entry.zig");
const serializer = @import("serializer.zig");
const argon2 = @import("../crypto/argon2.zig");
const xchacha = @import("../crypto/xchacha.zig");
const memory = @import("../memory/secure_allocator.zig");

pub const VaultError = error{
    VaultNotFound,
    VaultLocked,
    VaultCorrupted,
    InvalidMasterPassword,
    EntryNotFound,
    EntryAlreadyExists,
    IoError,
    CryptoError,
    InvalidMagic,
    UnsupportedVersion,
};

pub const VAULT_MAGIC: [4]u8 = .{ 'Z', 'A', 'U', 'L' };
pub const VAULT_VERSION: u16 = 1;

pub const VaultHeader = struct {
    magic: [4]u8 = VAULT_MAGIC,
    version: u16 = VAULT_VERSION,
    kdf_algorithm: u8 = 1,
    encryption_algorithm: u8 = 1,
    kdf_memory: u32 = 65536,
    kdf_iterations: u32 = 3,
    kdf_parallelism: u8 = 4,
    salt: [argon2.salt_length]u8,
    nonce: [xchacha.nonce_length]u8,
    reserved: [16]u8 = [_]u8{0} ** 16,

    pub const SIZE: usize = 4 + 2 + 1 + 1 + 4 + 4 + 1 + argon2.salt_length + xchacha.nonce_length + 16;

    pub fn serialize(self: *const VaultHeader) [SIZE]u8 {
        var buf: [SIZE]u8 = undefined;
        var offset: usize = 0;

        @memcpy(buf[offset..][0..4], &self.magic);
        offset += 4;

        std.mem.writeInt(u16, buf[offset..][0..2], self.version, .little);
        offset += 2;

        buf[offset] = self.kdf_algorithm;
        offset += 1;

        buf[offset] = self.encryption_algorithm;
        offset += 1;

        std.mem.writeInt(u32, buf[offset..][0..4], self.kdf_memory, .little);
        offset += 4;

        std.mem.writeInt(u32, buf[offset..][0..4], self.kdf_iterations, .little);
        offset += 4;

        buf[offset] = self.kdf_parallelism;
        offset += 1;

        @memcpy(buf[offset..][0..argon2.salt_length], &self.salt);
        offset += argon2.salt_length;

        @memcpy(buf[offset..][0..xchacha.nonce_length], &self.nonce);
        offset += xchacha.nonce_length;

        @memcpy(buf[offset..][0..16], &self.reserved);

        return buf;
    }

    pub fn deserialize(buf: *const [SIZE]u8) !VaultHeader {
        var offset: usize = 0;

        const magic = buf[offset..][0..4].*;
        offset += 4;

        if (!std.mem.eql(u8, &magic, &VAULT_MAGIC)) {
            return VaultError.InvalidMagic;
        }

        const version = std.mem.readInt(u16, buf[offset..][0..2], .little);
        offset += 2;

        if (version != VAULT_VERSION) {
            return VaultError.UnsupportedVersion;
        }

        const kdf_algorithm = buf[offset];
        offset += 1;

        const encryption_algorithm = buf[offset];
        offset += 1;

        const kdf_memory = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;

        const kdf_iterations = std.mem.readInt(u32, buf[offset..][0..4], .little);
        offset += 4;

        const kdf_parallelism = buf[offset];
        offset += 1;

        const salt = buf[offset..][0..argon2.salt_length].*;
        offset += argon2.salt_length;

        const nonce = buf[offset..][0..xchacha.nonce_length].*;
        offset += xchacha.nonce_length;

        const reserved = buf[offset..][0..16].*;

        return VaultHeader{
            .magic = magic,
            .version = version,
            .kdf_algorithm = kdf_algorithm,
            .encryption_algorithm = encryption_algorithm,
            .kdf_memory = kdf_memory,
            .kdf_iterations = kdf_iterations,
            .kdf_parallelism = kdf_parallelism,
            .salt = salt,
            .nonce = nonce,
            .reserved = reserved,
        };
    }
};

pub const Vault = struct {
    allocator: std.mem.Allocator,
    header: VaultHeader,
    entries: std.ArrayList(entry.Entry),
    is_locked: bool,
    path: []const u8,
    derived_key: ?[argon2.key_length]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8) Self {
        return Self{
            .allocator = allocator,
            .header = VaultHeader{
                .salt = undefined,
                .nonce = undefined,
            },
            .entries = .empty,
            .is_locked = true,
            .path = path,
            .derived_key = null,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |*e| {
            e.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);

        if (self.derived_key) |*key| {
            memory.secureZero(key);
        }
    }

    pub fn create(allocator: std.mem.Allocator, path: []const u8, master_password: []const u8) !Self {
        var vault = Self.init(allocator, path);

        std.crypto.random.bytes(&vault.header.salt);
        std.crypto.random.bytes(&vault.header.nonce);

        const params = argon2.Params{
            .t = vault.header.kdf_iterations,
            .m = vault.header.kdf_memory,
            .p = @intCast(vault.header.kdf_parallelism),
        };

        vault.derived_key = try argon2.deriveKey(
            allocator,
            master_password,
            &vault.header.salt,
            params,
        );
        vault.is_locked = false;

        return vault;
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) !Self {
        const file = std.fs.cwd().openFile(path, .{}) catch return VaultError.VaultNotFound;
        defer file.close();

        var header_buf: [VaultHeader.SIZE]u8 = undefined;
        const header_bytes_read = file.readAll(&header_buf) catch return VaultError.IoError;
        if (header_bytes_read != VaultHeader.SIZE) {
            return VaultError.VaultCorrupted;
        }

        const header = VaultHeader.deserialize(&header_buf) catch return VaultError.VaultCorrupted;

        return Self{
            .allocator = allocator,
            .header = header,
            .entries = .empty,
            .is_locked = true,
            .path = path,
            .derived_key = null,
        };
    }

    pub fn unlock(self: *Self, master_password: []const u8) !void {
        const params = argon2.Params{
            .t = self.header.kdf_iterations,
            .m = self.header.kdf_memory,
            .p = @intCast(self.header.kdf_parallelism),
        };

        self.derived_key = try argon2.deriveKey(
            self.allocator,
            master_password,
            &self.header.salt,
            params,
        );
        errdefer {
            if (self.derived_key) |*key| {
                memory.secureZero(key);
                self.derived_key = null;
            }
        }

        const file = std.fs.cwd().openFile(self.path, .{}) catch return VaultError.VaultNotFound;
        defer file.close();

        file.seekTo(VaultHeader.SIZE) catch return VaultError.IoError;

        const file_stat = file.stat() catch return VaultError.IoError;
        if (file_stat.size < VaultHeader.SIZE) {
            return VaultError.VaultCorrupted;
        }
        const encrypted_size = file_stat.size - VaultHeader.SIZE;

        if (encrypted_size < xchacha.tag_length) {
            self.is_locked = false;
            return;
        }

        const encrypted_data = self.allocator.alloc(u8, encrypted_size) catch return VaultError.IoError;
        defer self.allocator.free(encrypted_data);

        const bytes_read = file.readAll(encrypted_data) catch return VaultError.IoError;
        if (bytes_read != encrypted_size) {
            return VaultError.VaultCorrupted;
        }

        const ciphertext_len = encrypted_size - xchacha.tag_length;
        const ciphertext = encrypted_data[0..ciphertext_len];
        const tag = encrypted_data[ciphertext_len..][0..xchacha.tag_length];

        const plaintext = self.allocator.alloc(u8, ciphertext_len) catch return VaultError.IoError;
        defer self.allocator.free(plaintext);

        xchacha.decrypt(
            plaintext,
            ciphertext,
            tag,
            &self.derived_key.?,
            &self.header.nonce,
        ) catch return VaultError.InvalidMasterPassword;

        const entries = serializer.deserializeEntries(self.allocator, plaintext) catch return VaultError.VaultCorrupted;

        for (entries) |e| {
            self.entries.append(self.allocator, e) catch {
                for (entries) |*ent| {
                    var mut_ent = ent.*;
                    mut_ent.deinit(self.allocator);
                }
                self.allocator.free(entries);
                return VaultError.IoError;
            };
        }
        self.allocator.free(entries);

        self.is_locked = false;
    }

    pub fn unlockWithKey(self: *Self, key: [argon2.key_length]u8) !void {
        self.derived_key = key;
        errdefer {
            if (self.derived_key) |*k| {
                memory.secureZero(k);
                self.derived_key = null;
            }
        }

        const file = std.fs.cwd().openFile(self.path, .{}) catch return VaultError.VaultNotFound;
        defer file.close();

        file.seekTo(VaultHeader.SIZE) catch return VaultError.IoError;

        const file_stat = file.stat() catch return VaultError.IoError;
        if (file_stat.size < VaultHeader.SIZE) {
            return VaultError.VaultCorrupted;
        }
        const encrypted_size = file_stat.size - VaultHeader.SIZE;

        if (encrypted_size < xchacha.tag_length) {
            self.is_locked = false;
            return;
        }

        const encrypted_data = self.allocator.alloc(u8, encrypted_size) catch return VaultError.IoError;
        defer self.allocator.free(encrypted_data);

        const bytes_read = file.readAll(encrypted_data) catch return VaultError.IoError;
        if (bytes_read != encrypted_size) {
            return VaultError.VaultCorrupted;
        }

        const ciphertext_len = encrypted_size - xchacha.tag_length;
        const ciphertext = encrypted_data[0..ciphertext_len];
        const tag = encrypted_data[ciphertext_len..][0..xchacha.tag_length];

        const plaintext = self.allocator.alloc(u8, ciphertext_len) catch return VaultError.IoError;
        defer self.allocator.free(plaintext);

        xchacha.decrypt(
            plaintext,
            ciphertext,
            tag,
            &self.derived_key.?,
            &self.header.nonce,
        ) catch return VaultError.InvalidMasterPassword;

        const entries = serializer.deserializeEntries(self.allocator, plaintext) catch return VaultError.VaultCorrupted;

        for (entries) |e| {
            self.entries.append(self.allocator, e) catch {
                for (entries) |*ent| {
                    var mut_ent = ent.*;
                    mut_ent.deinit(self.allocator);
                }
                self.allocator.free(entries);
                return VaultError.IoError;
            };
        }
        self.allocator.free(entries);

        self.is_locked = false;
    }

    pub fn lock(self: *Self) void {
        for (self.entries.items) |*e| {
            e.deinit(self.allocator);
        }
        self.entries.clearRetainingCapacity();

        if (self.derived_key) |*key| {
            memory.secureZero(key);
            self.derived_key = null;
        }

        self.is_locked = true;
    }

    pub fn save(self: *Self) !void {
        if (self.is_locked) {
            return VaultError.VaultLocked;
        }

        const key = self.derived_key orelse return VaultError.VaultLocked;

        std.crypto.random.bytes(&self.header.nonce);

        const plaintext = serializer.serializeEntries(self.allocator, self.entries.items) catch return VaultError.IoError;
        defer {
            memory.secureZero(plaintext);
            self.allocator.free(plaintext);
        }

        const ciphertext = self.allocator.alloc(u8, plaintext.len) catch return VaultError.IoError;
        defer self.allocator.free(ciphertext);

        var tag: [xchacha.tag_length]u8 = undefined;

        xchacha.encrypt(ciphertext, &tag, plaintext, &key, &self.header.nonce) catch return VaultError.CryptoError;

        const dir_path = std.fs.path.dirname(self.path);
        if (dir_path) |dp| {
            std.fs.cwd().makePath(dp) catch {};
        }

        const file = std.fs.cwd().createFile(self.path, .{ .mode = 0o600 }) catch return VaultError.IoError;
        defer file.close();

        const header_bytes = self.header.serialize();
        file.writeAll(&header_bytes) catch return VaultError.IoError;
        file.writeAll(ciphertext) catch return VaultError.IoError;
        file.writeAll(&tag) catch return VaultError.IoError;
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

        try self.entries.append(self.allocator, new_entry);
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

        for (self.entries.items, 0..) |*e, i| {
            if (std.mem.eql(u8, e.name, name)) {
                e.deinit(self.allocator);
                _ = self.entries.orderedRemove(i);
                return;
            }
        }

        return VaultError.EntryNotFound;
    }
};

pub fn getDefaultVaultDataPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
    const data_home = std.posix.getenv("XDG_DATA_HOME");

    if (data_home) |data| {
        return std.fmt.allocPrint(allocator, "{s}/zault/vault.zault", .{data});
    } else {
        return std.fmt.allocPrint(allocator, "{s}/.local/share/zault/vault.zault", .{home});
    }
}

pub fn getDefaultVaultDataDir(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
    const data_home = std.posix.getenv("XDG_DATA_HOME");

    if (data_home) |data| {
        return std.fmt.allocPrint(allocator, "{s}/zault", .{data});
    } else {
        return std.fmt.allocPrint(allocator, "{s}/.local/share/zault", .{home});
    }
}

pub fn getLegacyVaultPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
    const config_home = std.posix.getenv("XDG_CONFIG_HOME");

    if (config_home) |config| {
        return std.fmt.allocPrint(allocator, "{s}/zault/vault.zault", .{config});
    } else {
        return std.fmt.allocPrint(allocator, "{s}/.config/zault/vault.zault", .{home});
    }
}

pub fn checkLegacyVaultExists(allocator: std.mem.Allocator) !bool {
    const legacy_path = try getLegacyVaultPath(allocator);
    defer allocator.free(legacy_path);

    std.fs.cwd().access(legacy_path, .{}) catch return false;
    return true;
}

test "vault init" {
    const allocator = std.testing.allocator;
    var vault = Vault.init(allocator, "/tmp/test.zault");
    defer vault.deinit();

    try std.testing.expect(vault.is_locked);
    try std.testing.expectEqual(@as(usize, 0), vault.entries.items.len);
}

test "vault header serialize deserialize" {
    var header = VaultHeader{
        .salt = [_]u8{1} ** argon2.salt_length,
        .nonce = [_]u8{2} ** xchacha.nonce_length,
    };

    const serialized = header.serialize();
    const deserialized = try VaultHeader.deserialize(&serialized);

    try std.testing.expectEqualSlices(u8, &header.magic, &deserialized.magic);
    try std.testing.expectEqual(header.version, deserialized.version);
    try std.testing.expectEqualSlices(u8, &header.salt, &deserialized.salt);
    try std.testing.expectEqualSlices(u8, &header.nonce, &deserialized.nonce);
}

test "vault create save open unlock roundtrip" {
    const allocator = std.testing.allocator;
    const test_path = "/tmp/zault_test_vault.zault";

    defer std.fs.cwd().deleteFile(test_path) catch {};

    {
        var vault = try Vault.create(allocator, test_path, "testpassword123");
        defer vault.deinit();

        const e = try entry.createPasswordEntry(
            allocator,
            "github.com",
            "testuser",
            "secretpassword",
            "https://github.com",
        );
        try vault.addEntry(e);

        try vault.save();
    }

    {
        var vault = try Vault.open(allocator, test_path);
        defer vault.deinit();

        try std.testing.expect(vault.is_locked);

        try vault.unlock("testpassword123");

        try std.testing.expect(!vault.is_locked);
        try std.testing.expectEqual(@as(usize, 1), vault.entries.items.len);

        const retrieved = vault.getEntry("github.com");
        try std.testing.expect(retrieved != null);
        try std.testing.expectEqualStrings("testuser", retrieved.?.data.password.username.?);
    }
}

test "vault wrong password fails" {
    const allocator = std.testing.allocator;
    const test_path = "/tmp/zault_test_wrong_pw.zault";

    defer std.fs.cwd().deleteFile(test_path) catch {};

    {
        var vault = try Vault.create(allocator, test_path, "correctpassword");
        defer vault.deinit();

        const e = try entry.createPasswordEntry(allocator, "test", null, "pass", null);
        try vault.addEntry(e);
        try vault.save();
    }

    {
        var vault = try Vault.open(allocator, test_path);
        defer vault.deinit();

        const result = vault.unlock("wrongpassword");
        try std.testing.expectError(VaultError.InvalidMasterPassword, result);
    }
}
