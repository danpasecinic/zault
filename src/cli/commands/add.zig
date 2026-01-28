const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const item = @import("../../core/item.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const item_name = if (args.len > 0)
        args[0]
    else blk: {
        const name = terminal.readLine(allocator, "Item name: ") catch {
            std.debug.print("Error: Could not read item name\n", .{});
            return;
        };
        if (name.len == 0) {
            allocator.free(name);
            std.debug.print("Error: Item name cannot be empty\n", .{});
            return;
        }
        break :blk name;
    };
    const should_free_name = args.len == 0;
    defer if (should_free_name) allocator.free(item_name);

    const username = terminal.readLine(allocator, "Username (optional): ") catch {
        std.debug.print("Error: Could not read username\n", .{});
        return;
    };
    defer allocator.free(username);
    const username_opt: ?[]const u8 = if (username.len > 0) username else null;

    const item_password = terminal.readPassword(allocator, "Password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(item_password);
        allocator.free(item_password);
    }

    if (item_password.len == 0) {
        std.debug.print("Error: Password cannot be empty\n", .{});
        return;
    }

    const url = terminal.readLine(allocator, "URL (optional): ") catch {
        std.debug.print("Error: Could not read URL\n", .{});
        return;
    };
    defer allocator.free(url);
    const url_opt: ?[]const u8 = if (url.len > 0) url else null;

    const new_item = item.createLoginItem(
        allocator,
        item_name,
        username_opt,
        item_password,
        url_opt,
    ) catch {
        std.debug.print("Error: Could not create item\n", .{});
        return;
    };

    ctx.vault.addItem(new_item) catch |err| {
        var mutable_item = new_item;
        mutable_item.deinit(allocator);
        switch (err) {
            core.VaultError.ItemAlreadyExists => {
                std.debug.print("Error: Item '{s}' already exists\n", .{item_name});
            },
            else => {
                std.debug.print("Error: Could not add item\n", .{});
            },
        }
        return;
    };

    ctx.vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Item '{s}' added successfully.\n", .{item_name});
}
