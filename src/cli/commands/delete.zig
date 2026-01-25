const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault delete <name>\n", .{});
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

    std.debug.print("Delete entry '{s}'? [y/N]: ", .{entry_name});
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    var buf: [1]u8 = undefined;
    const bytes_read = stdin.read(&buf) catch 0;
    const confirmed = bytes_read > 0 and (buf[0] == 'y' or buf[0] == 'Y');
    if (!confirmed) {
        std.debug.print("Cancelled.\n", .{});
        return;
    }

    vault.deleteEntry(entry_name) catch |err| {
        switch (err) {
            core.VaultError.EntryNotFound => {
                std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
            },
            else => {
                std.debug.print("Error: Could not delete entry\n", .{});
            },
        }
        return;
    };

    vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Entry '{s}' deleted.\n", .{entry_name});
}
