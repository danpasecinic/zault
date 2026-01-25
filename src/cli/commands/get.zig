const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");
const clipboard = @import("../../services/clipboard.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault get <name>\n", .{});
        return;
    }

    const entry_name = args[0];

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

    const found_entry = vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    const e = found_entry.?;
    switch (e.data) {
        .password => |pwd| {
            if (!cfg.clipboard_enabled) {
                std.debug.print("Clipboard disabled in config. Password for '{s}':\n{s}\n", .{ entry_name, pwd.password });
                return;
            }

            clipboard.copyWithTimeout(allocator, pwd.password, cfg.clipboard_timeout) catch {
                std.debug.print("Error: Could not copy to clipboard. Password:\n{s}\n", .{pwd.password});
                return;
            };

            std.debug.print("Password for '{s}' copied to clipboard.", .{entry_name});
            if (cfg.clipboard_timeout > 0) {
                std.debug.print(" Clearing in {d}s.", .{cfg.clipboard_timeout});
            }
            std.debug.print("\n", .{});

            if (pwd.username) |u| {
                std.debug.print("Username: {s}\n", .{u});
            }
            if (pwd.url) |url| {
                std.debug.print("URL: {s}\n", .{url});
            }
        },
        .totp => {
            std.debug.print("Entry '{s}' is a TOTP entry. Use 'zault totp {s}' instead.\n", .{ entry_name, entry_name });
        },
        .passkey => {
            std.debug.print("Entry '{s}' is a passkey entry.\n", .{entry_name});
        },
    }
}
