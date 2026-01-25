const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const entry = @import("../../core/entry.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const entry_name = if (args.len > 0)
        args[0]
    else blk: {
        const name = terminal.readLine(allocator, "Entry name: ") catch {
            std.debug.print("Error: Could not read entry name\n", .{});
            return;
        };
        if (name.len == 0) {
            allocator.free(name);
            std.debug.print("Error: Entry name cannot be empty\n", .{});
            return;
        }
        break :blk name;
    };
    const should_free_name = args.len == 0;
    defer if (should_free_name) allocator.free(entry_name);

    const username = terminal.readLine(allocator, "Username (optional): ") catch {
        std.debug.print("Error: Could not read username\n", .{});
        return;
    };
    defer allocator.free(username);
    const username_opt: ?[]const u8 = if (username.len > 0) username else null;

    const entry_password = terminal.readPassword(allocator, "Password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(entry_password);
        allocator.free(entry_password);
    }

    if (entry_password.len == 0) {
        std.debug.print("Error: Password cannot be empty\n", .{});
        return;
    }

    const url = terminal.readLine(allocator, "URL (optional): ") catch {
        std.debug.print("Error: Could not read URL\n", .{});
        return;
    };
    defer allocator.free(url);
    const url_opt: ?[]const u8 = if (url.len > 0) url else null;

    const new_entry = entry.createPasswordEntry(
        allocator,
        entry_name,
        username_opt,
        entry_password,
        url_opt,
    ) catch {
        std.debug.print("Error: Could not create entry\n", .{});
        return;
    };

    ctx.vault.addEntry(new_entry) catch |err| {
        var mutable_entry = new_entry;
        mutable_entry.deinit(allocator);
        switch (err) {
            core.VaultError.EntryAlreadyExists => {
                std.debug.print("Error: Entry '{s}' already exists\n", .{entry_name});
            },
            else => {
                std.debug.print("Error: Could not add entry\n", .{});
            },
        }
        return;
    };

    ctx.vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Entry '{s}' added successfully.\n", .{entry_name});
}
