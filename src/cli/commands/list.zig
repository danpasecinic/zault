const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");

pub fn run(allocator: std.mem.Allocator, _: []const []const u8, _: config.Config) !void {
    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
            },
        }
        return;
    };
    defer vault.deinit();

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
            },
        }
        return;
    };

    if (vault.entries.items.len == 0) {
        std.debug.print("Vault is empty. Use 'zault add <name>' to add entries.\n", .{});
        return;
    }

    std.debug.print("Entries ({d}):\n", .{vault.entries.items.len});
    std.debug.print("{s:<30} {s:<12} {s}\n", .{ "NAME", "TYPE", "USERNAME/ISSUER" });
    std.debug.print("{s}\n", .{"-" ** 60});

    for (vault.entries.items) |e| {
        const type_str = switch (e.entry_type) {
            .password => "password",
            .totp => "totp",
            .passkey => "passkey",
        };

        const extra = switch (e.data) {
            .password => |p| p.username orelse "",
            .totp => |t| t.issuer orelse "",
            .passkey => |pk| pk.user_name orelse "",
        };

        std.debug.print("{s:<30} {s:<12} {s}\n", .{ e.name, type_str, extra });
    }
}
