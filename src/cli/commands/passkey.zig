const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
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
    for (ctx.vault.entries.items) |e| {
        if (e.entry_type == .passkey) {
            count += 1;
        }
    }

    if (count == 0) {
        std.debug.print("No passkey entries found.\n", .{});
        return;
    }

    std.debug.print("Passkey Entries ({d}):\n", .{count});
    std.debug.print("{s:<25} {s:<30} {s}\n", .{ "NAME", "RP ID", "USER" });
    std.debug.print("{s}\n", .{"-" ** 70});

    for (ctx.vault.entries.items) |e| {
        if (e.entry_type == .passkey) {
            const pk = e.data.passkey;
            const user = pk.user_name orelse "";
            std.debug.print("{s:<25} {s:<30} {s}\n", .{ e.name, pk.rp_id, user });
        }
    }
}

fn runShow(allocator: std.mem.Allocator, entry_name: []const u8) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_entry = ctx.vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    const e = found_entry.?;
    if (e.entry_type != .passkey) {
        std.debug.print("Error: Entry '{s}' is not a passkey\n", .{entry_name});
        return;
    }

    const pk = e.data.passkey;
    const algo_str = switch (pk.algorithm) {
        .es256 => "ES256 (P-256)",
        .ed25519 => "Ed25519",
        .rs256 => "RS256",
    };

    std.debug.print("\nPasskey: {s}\n", .{e.name});
    std.debug.print("{s}\n", .{"-" ** 40});
    std.debug.print("Relying Party ID: {s}\n", .{pk.rp_id});
    if (pk.rp_name) |rp_name| {
        std.debug.print("Relying Party Name: {s}\n", .{rp_name});
    }
    if (pk.user_name) |user_name| {
        std.debug.print("User Name: {s}\n", .{user_name});
    }
    std.debug.print("Algorithm: {s}\n", .{algo_str});
    std.debug.print("Sign Count: {d}\n", .{pk.counter});
    std.debug.print("Credential ID: {s}...\n", .{pk.credential_id[0..@min(16, pk.credential_id.len)]});
}

fn runDelete(allocator: std.mem.Allocator, entry_name: []const u8) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_entry = ctx.vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    if (found_entry.?.entry_type != .passkey) {
        std.debug.print("Error: Entry '{s}' is not a passkey\n", .{entry_name});
        return;
    }

    std.debug.print("Delete passkey '{s}'? [y/N]: ", .{entry_name});
    if (!confirm()) {
        std.debug.print("Cancelled.\n", .{});
        return;
    }

    ctx.vault.deleteEntry(entry_name) catch |err| {
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

    ctx.vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Passkey '{s}' deleted.\n", .{entry_name});
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
        \\    list              List all passkey entries
        \\    show <name>       Show passkey details
        \\    delete <name>     Delete a passkey entry
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
