const std = @import("std");
const config = @import("../../core/config.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, _: []const []const u8, _: config.Config) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    if (ctx.vault.entries.items.len == 0) {
        std.debug.print("Vault is empty. Use 'zault add <name>' to add entries.\n", .{});
        return;
    }

    std.debug.print("Entries ({d}):\n", .{ctx.vault.entries.items.len});
    std.debug.print("{s:<30} {s:<12} {s}\n", .{ "NAME", "TYPE", "USERNAME/ISSUER" });
    std.debug.print("{s}\n", .{"-" ** 60});

    for (ctx.vault.entries.items) |e| {
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
