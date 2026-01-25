const std = @import("std");
const config = @import("../../core/config.zig");
const clipboard = @import("../../services/clipboard.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault get <name>\n", .{});
        return;
    }

    const entry_name = args[0];

    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_entry = ctx.vault.getEntry(entry_name);
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
