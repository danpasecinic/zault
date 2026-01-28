const std = @import("std");
const config = @import("../../core/config.zig");
const clipboard = @import("../../services/clipboard.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault get <name>\n", .{});
        return;
    }

    const item_name = args[0];

    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_item = ctx.vault.getItem(item_name);
    if (found_item == null) {
        std.debug.print("Error: Item '{s}' not found\n", .{item_name});
        return;
    }

    const i = found_item.?;
    switch (i.data) {
        .login => |login| {
            const password = login.password orelse {
                std.debug.print("Item '{s}' has no password set.\n", .{item_name});
                return;
            };

            if (!cfg.clipboard_enabled) {
                std.debug.print("Clipboard disabled in config. Password for '{s}':\n{s}\n", .{ item_name, password });
                return;
            }

            clipboard.copyWithTimeout(allocator, password, cfg.clipboard_timeout) catch {
                std.debug.print("Error: Could not copy to clipboard. Password:\n{s}\n", .{password});
                return;
            };

            std.debug.print("Password for '{s}' copied to clipboard.", .{item_name});
            if (cfg.clipboard_timeout > 0) {
                std.debug.print(" Clearing in {d}s.", .{cfg.clipboard_timeout});
            }
            std.debug.print("\n", .{});

            if (login.username) |u| {
                std.debug.print("Username: {s}\n", .{u});
            }
            if (login.uris.len > 0) {
                std.debug.print("URL: {s}\n", .{login.uris[0].uri});
            }
        },
        .card => {
            std.debug.print("Item '{s}' is a card. Use 'zault card {s}' instead.\n", .{ item_name, item_name });
        },
        .secure_note => {
            if (i.notes) |notes| {
                std.debug.print("Note:\n{s}\n", .{notes});
            } else {
                std.debug.print("Item '{s}' has no notes.\n", .{item_name});
            }
        },
        .identity => {
            std.debug.print("Item '{s}' is an identity.\n", .{item_name});
        },
        .ssh_key => {
            std.debug.print("Item '{s}' is an SSH key.\n", .{item_name});
        },
        .api_credential => {
            std.debug.print("Item '{s}' is an API credential.\n", .{item_name});
        },
        .database => {
            std.debug.print("Item '{s}' is a database credential.\n", .{item_name});
        },
        .wifi => {
            std.debug.print("Item '{s}' is a WiFi credential.\n", .{item_name});
        },
        .license => {
            std.debug.print("Item '{s}' is a software license.\n", .{item_name});
        },
    }
}
