const std = @import("std");
const core = @import("../core/vault.zig");
const terminal = @import("terminal.zig");
const memory = @import("../memory/secure_allocator.zig");
const agent = @import("../services/agent.zig");

pub const OpenError = error{
    VaultPathError,
    VaultNotFound,
    VaultOpenError,
    PasswordReadError,
    InvalidPassword,
    UnlockError,
};

pub const VaultContext = struct {
    vault: core.Vault,
    vault_path: []const u8,
    password: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VaultContext) void {
        self.vault.deinit();
        memory.secureZero(self.password);
        self.allocator.free(self.password);
        self.allocator.free(self.vault_path);
    }
};

pub fn openAndUnlock(allocator: std.mem.Allocator) OpenError!VaultContext {
    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return OpenError.VaultPathError;
    };
    errdefer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
                return OpenError.VaultNotFound;
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
                return OpenError.VaultOpenError;
            },
        }
    };
    errdefer vault.deinit();

    var client = agent.AgentClient.init(allocator) catch null;
    defer if (client) |*c| c.deinit();

    if (client) |*c| {
        if (c.getKey()) |key| {
            var mutable_key = key;
            defer memory.secureZero(&mutable_key);
            vault.unlockWithKey(key) catch |err| {
                if (err != core.VaultError.InvalidMasterPassword) {
                    std.log.warn("Agent key failed: {}", .{err});
                }
            };
            if (!vault.is_locked) {
                const empty_pass = allocator.alloc(u8, 0) catch return OpenError.PasswordReadError;
                return VaultContext{
                    .vault = vault,
                    .vault_path = vault_path,
                    .password = empty_pass,
                    .allocator = allocator,
                };
            }
        } else |_| {}
    }

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return OpenError.PasswordReadError;
    };
    errdefer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
                return OpenError.InvalidPassword;
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
                return OpenError.UnlockError;
            },
        }
    };

    return VaultContext{
        .vault = vault,
        .vault_path = vault_path,
        .password = password,
        .allocator = allocator,
    };
}
