const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const item = @import("../../core/item.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    if (args.len == 0) {
        showHelp();
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "list")) {
        try runList(allocator);
    } else if (std.mem.eql(u8, subcommand, "delete")) {
        if (args.len < 2) {
            std.debug.print("Usage: zault passkey delete <name>\n", .{});
            return;
        }
        try runDelete(allocator, args[1]);
    } else if (std.mem.eql(u8, subcommand, "show")) {
        if (args.len < 2) {
            std.debug.print("Usage: zault passkey show <name>\n", .{});
            return;
        }
        try runShow(allocator, args[1]);
    } else if (std.mem.eql(u8, subcommand, "help") or std.mem.eql(u8, subcommand, "--help")) {
        showHelp();
    } else {
        std.debug.print("Unknown subcommand: {s}\n", .{subcommand});
        showHelp();
    }
}

fn runList(allocator: std.mem.Allocator) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    var count: usize = 0;
    for (ctx.vault.items.items) |i| {
        if (i.item_type == .login and i.data.login.passkeys.len > 0) {
            count += i.data.login.passkeys.len;
        }
    }

    if (count == 0) {
        std.debug.print("No passkeys found.\n", .{});
        return;
    }

    std.debug.print("Passkeys ({d}):\n", .{count});
    std.debug.print("{s:<25} {s:<30} {s}\n", .{ "ITEM", "RP ID", "USER" });
    std.debug.print("{s}\n", .{"-" ** 70});

    for (ctx.vault.items.items) |i| {
        if (i.item_type == .login) {
            for (i.data.login.passkeys) |pk| {
                const user = pk.user_name orelse "";
                std.debug.print("{s:<25} {s:<30} {s}\n", .{ i.name, pk.rp_id, user });
            }
        }
    }
}

fn runShow(allocator: std.mem.Allocator, item_name: []const u8) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_item = ctx.vault.getItem(item_name);
    if (found_item == null) {
        std.debug.print("Error: Item '{s}' not found\n", .{item_name});
        return;
    }

    const i = found_item.?;
    if (i.item_type != .login) {
        std.debug.print("Error: Item '{s}' is not a login item\n", .{item_name});
        return;
    }

    if (i.data.login.passkeys.len == 0) {
        std.debug.print("Item '{s}' has no passkeys\n", .{item_name});
        return;
    }

    std.debug.print("\nPasskeys for '{s}':\n", .{i.name});
    std.debug.print("{s}\n", .{"-" ** 40});

    for (i.data.login.passkeys, 0..) |pk, idx| {
        const algo_str = switch (pk.algorithm) {
            .es256 => "ES256 (P-256)",
            .ed25519 => "Ed25519",
            .rs256 => "RS256",
        };

        std.debug.print("\nPasskey #{d}:\n", .{idx + 1});
        std.debug.print("  Relying Party ID: {s}\n", .{pk.rp_id});
        if (pk.rp_name) |rp_name| {
            std.debug.print("  Relying Party Name: {s}\n", .{rp_name});
        }
        if (pk.user_name) |user_name| {
            std.debug.print("  User Name: {s}\n", .{user_name});
        }
        std.debug.print("  Algorithm: {s}\n", .{algo_str});
        std.debug.print("  Sign Count: {d}\n", .{pk.counter});
        std.debug.print("  Credential ID: {s}...\n", .{pk.credential_id[0..@min(16, pk.credential_id.len)]});
    }
}

fn runDelete(allocator: std.mem.Allocator, item_name: []const u8) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_item = ctx.vault.getItem(item_name);
    if (found_item == null) {
        std.debug.print("Error: Item '{s}' not found\n", .{item_name});
        return;
    }

    const i = found_item.?;
    if (i.item_type != .login) {
        std.debug.print("Error: Item '{s}' is not a login item\n", .{item_name});
        return;
    }

    if (i.data.login.passkeys.len == 0) {
        std.debug.print("Item '{s}' has no passkeys\n", .{item_name});
        return;
    }

    std.debug.print("Delete all passkeys from '{s}'? [y/N]: ", .{item_name});
    if (!confirm()) {
        std.debug.print("Cancelled.\n", .{});
        return;
    }

    for (i.data.login.passkeys) |*pk| {
        pk.deinit(allocator);
    }
    allocator.free(i.data.login.passkeys);
    i.data.login.passkeys = &.{};
    i.modified_at = std.time.timestamp();

    ctx.vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Passkeys deleted from '{s}'.\n", .{item_name});
}

fn confirm() bool {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    var buf: [1]u8 = undefined;
    const bytes_read = stdin.read(&buf) catch return false;
    const result = bytes_read > 0 and (buf[0] == 'y' or buf[0] == 'Y');
    var discard: [16]u8 = undefined;
    _ = stdin.read(&discard) catch {};
    return result;
}

fn showHelp() void {
    const help =
        \\Usage: zault passkey <subcommand> [options]
        \\
        \\Subcommands:
        \\    list              List all passkeys
        \\    show <name>       Show passkey details for an item
        \\    delete <name>     Delete passkeys from an item
        \\
        \\Note: Passkeys are typically created through browser-based
        \\WebAuthn flows and stored in the vault by external tools.
        \\
        \\Examples:
        \\    zault passkey list
        \\    zault passkey show github.com
        \\    zault passkey delete github.com
        \\
    ;
    std.debug.print("{s}", .{help});
}
