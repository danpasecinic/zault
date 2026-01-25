const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault delete <name>\n", .{});
        return;
    }

    const entry_name = args[0];

    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    std.debug.print("Delete entry '{s}'? [y/N]: ", .{entry_name});
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

    std.debug.print("Entry '{s}' deleted.\n", .{entry_name});
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
