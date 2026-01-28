const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const item = @import("../../core/item.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");
const clipboard = @import("../../services/clipboard.zig");
const totp = @import("../../services/totp.zig");
const vault_helpers = @import("../vault_helpers.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    if (args.len == 0) {
        showHelp();
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "add")) {
        try runAdd(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "delete")) {
        if (args.len < 2) {
            std.debug.print("Usage: zault totp delete <name>\n", .{});
            return;
        }
        try runDelete(allocator, args[1]);
    } else if (std.mem.eql(u8, subcommand, "list")) {
        try runList(allocator);
    } else if (std.mem.eql(u8, subcommand, "help") or std.mem.eql(u8, subcommand, "--help")) {
        showHelp();
    } else {
        try runGet(allocator, subcommand, cfg);
    }
}

fn runAdd(allocator: std.mem.Allocator, args: []const []const u8) !void {
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

    const secret = terminal.readPassword(allocator, "TOTP Secret (base32): ") catch {
        std.debug.print("Error: Could not read secret\n", .{});
        return;
    };

    if (secret.len == 0) {
        allocator.free(secret);
        std.debug.print("Error: Secret cannot be empty\n", .{});
        return;
    }

    _ = totp.generateCurrent(secret, 30, 6, .sha1) catch |err| {
        memory.secureZero(secret);
        allocator.free(secret);
        switch (err) {
            totp.TotpError.Base32DecodeError => {
                std.debug.print("Error: Invalid base32 secret. Use only A-Z and 2-7.\n", .{});
            },
            else => {
                std.debug.print("Error: Invalid TOTP secret\n", .{});
            },
        }
        return;
    };

    const existing = ctx.vault.getItem(item_name);
    if (existing) |i| {
        if (i.item_type != .login) {
            memory.secureZero(secret);
            allocator.free(secret);
            std.debug.print("Error: Item '{s}' is not a login item\n", .{item_name});
            return;
        }

        if (i.data.login.totp) |*old_totp| {
            old_totp.deinit(allocator);
        }

        i.data.login.totp = .{
            .secret = secret,
            .algorithm = .sha1,
            .digits = 6,
            .period = 30,
        };
        i.modified_at = std.time.timestamp();

        ctx.vault.save() catch {
            std.debug.print("Error: Could not save vault\n", .{});
            return;
        };

        std.debug.print("TOTP added to existing item '{s}'.\n", .{item_name});
        return;
    }

    memory.secureZero(secret);
    allocator.free(secret);
    std.debug.print("Error: Item '{s}' not found. Create it first with 'zault add {s}'.\n", .{ item_name, item_name });
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

    if (i.data.login.totp == null) {
        std.debug.print("Item '{s}' has no TOTP configured.\n", .{item_name});
        return;
    }

    i.data.login.totp.?.deinit(allocator);
    i.data.login.totp = null;
    i.modified_at = std.time.timestamp();

    ctx.vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };
    std.debug.print("TOTP removed from '{s}'.\n", .{item_name});
}

fn runGet(allocator: std.mem.Allocator, item_name: []const u8, cfg: config.Config) !void {
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

    const t = i.data.login.totp orelse {
        std.debug.print("Item '{s}' has no TOTP configured. Use 'zault totp add {s}' to add one.\n", .{ item_name, item_name });
        return;
    };

    try generateAndShowCode(allocator, t.secret, t.algorithm, t.digits, t.period, cfg);
}

fn generateAndShowCode(
    allocator: std.mem.Allocator,
    secret: []const u8,
    algorithm: item.TotpAlgorithm,
    digits: u8,
    period: u32,
    cfg: config.Config,
) !void {
    const algo: totp.Algorithm = switch (algorithm) {
        .sha1 => .sha1,
        .sha256 => .sha256,
        .sha512 => .sha512,
    };

    const code = totp.generateCurrent(secret, period, digits, algo) catch |err| {
        switch (err) {
            totp.TotpError.Base32DecodeError => {
                std.debug.print("Error: Invalid TOTP secret (must be valid base32)\n", .{});
            },
            totp.TotpError.InvalidSecret => {
                std.debug.print("Error: Invalid TOTP secret\n", .{});
            },
            else => {
                std.debug.print("Error: Could not generate TOTP code\n", .{});
            },
        }
        return;
    };

    const remaining = totp.getTimeRemaining(period);

    var code_str: [8]u8 = undefined;
    defer memory.secureZero(&code_str);

    const code_slice = std.fmt.bufPrint(&code_str, "{d:0>6}", .{code}) catch {
        std.debug.print("Error: Could not format TOTP code\n", .{});
        return;
    };

    std.debug.print("{s} (expires in {d}s)\n", .{ code_slice, remaining });

    if (cfg.clipboard_enabled) {
        clipboard.copyWithTimeout(allocator, code_slice, cfg.clipboard_timeout) catch {
            return;
        };
        std.debug.print("Copied to clipboard.\n", .{});
    }
}

fn runList(allocator: std.mem.Allocator) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    var count: usize = 0;
    for (ctx.vault.item_list.items) |i| {
        if (i.item_type == .login and i.data.login.totp != null) {
            count += 1;
        }
    }

    if (count == 0) {
        std.debug.print("No items with TOTP. Use 'zault totp add <name>' to add one.\n", .{});
        return;
    }

    std.debug.print("Items with TOTP ({d}):\n", .{count});
    std.debug.print("{s:<30} {s}\n", .{ "NAME", "USERNAME" });
    std.debug.print("{s}\n", .{"-" ** 45});

    for (ctx.vault.item_list.items) |i| {
        if (i.item_type == .login and i.data.login.totp != null) {
            const username = i.data.login.username orelse "";
            std.debug.print("{s:<30} {s}\n", .{ i.name, username });
        }
    }
}

fn showHelp() void {
    const help =
        \\Usage: zault totp <subcommand> [options]
        \\
        \\Subcommands:
        \\    add <name>      Add TOTP to a login item
        \\    delete <name>   Remove TOTP from a login item
        \\    list            List all items with TOTP
        \\    <name>          Get current TOTP code for item
        \\
        \\Examples:
        \\    zault totp add github.com
        \\    zault totp github.com
        \\    zault totp delete github.com
        \\    zault totp list
        \\
    ;
    std.debug.print("{s}", .{help});
}
