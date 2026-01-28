const std = @import("std");
const config = @import("../../core/config.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, _: []const []const u8, _: config.Config) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    if (ctx.vault.item_list.items.len == 0) {
        std.debug.print("Vault is empty. Use 'zault add <name>' to add items.\n", .{});
        return;
    }

    std.debug.print("Items ({d}):\n", .{ctx.vault.item_list.items.len});
    std.debug.print("{s:<30} {s:<12} {s}\n", .{ "NAME", "TYPE", "USERNAME/INFO" });
    std.debug.print("{s}\n", .{"-" ** 60});

    for (ctx.vault.item_list.items) |i| {
        const type_str = switch (i.item_type) {
            .login => "login",
            .secure_note => "note",
            .card => "card",
            .identity => "identity",
            .ssh_key => "ssh_key",
            .api_credential => "api",
            .database => "database",
            .wifi => "wifi",
            .license => "license",
        };

        const extra: []const u8 = switch (i.data) {
            .login => |l| l.username orelse "",
            .card => |c| c.cardholder_name orelse "",
            .identity => |id| id.first_name orelse "",
            .ssh_key => |s| @tagName(s.key_type),
            .api_credential => |a| a.endpoint orelse "",
            .database => |d| d.database orelse "",
            .wifi => |w| w.ssid,
            .license => |lic| lic.product_name orelse "",
            .secure_note => "",
        };

        std.debug.print("{s:<30} {s:<12} {s}\n", .{ i.name, type_str, extra });
    }
}
