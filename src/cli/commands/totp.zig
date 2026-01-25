const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const entry = @import("../../core/entry.zig");
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

    const existing = ctx.vault.getEntry(entry_name);
    if (existing) |e| {
        if (e.entry_type == .password) {
            if (e.data.password.totp_secret) |old_secret| {
                @memset(@constCast(old_secret), 0);
                allocator.free(old_secret);
            }
            e.data.password.totp_secret = secret;
            e.data.password.totp_algorithm = .sha1;
            e.data.password.totp_digits = 6;
            e.data.password.totp_period = 30;
            e.modified_at = std.time.timestamp();

            ctx.vault.save() catch {
                std.debug.print("Error: Could not save vault\n", .{});
                return;
            };

            std.debug.print("TOTP added to existing entry '{s}'.\n", .{entry_name});
            return;
        } else {
            memory.secureZero(secret);
            allocator.free(secret);
            std.debug.print("Error: Entry '{s}' exists but is not a password entry\n", .{entry_name});
            return;
        }
    }

    const issuer = terminal.readLine(allocator, "Issuer (optional): ") catch {
        memory.secureZero(secret);
        allocator.free(secret);
        std.debug.print("Error: Could not read issuer\n", .{});
        return;
    };
    defer allocator.free(issuer);
    const issuer_opt: ?[]const u8 = if (issuer.len > 0) issuer else null;

    const new_entry = entry.createTotpEntry(
        allocator,
        entry_name,
        secret,
        issuer_opt,
        .sha1,
        6,
        30,
    ) catch {
        memory.secureZero(secret);
        allocator.free(secret);
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

    std.debug.print("TOTP entry '{s}' added successfully.\n", .{entry_name});
}

fn runDelete(allocator: std.mem.Allocator, entry_name: []const u8) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_entry = ctx.vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    const e = found_entry.?;
    switch (e.data) {
        .totp => {
            ctx.vault.deleteEntry(entry_name) catch {
                std.debug.print("Error: Could not delete entry\n", .{});
                return;
            };
            ctx.vault.save() catch {
                std.debug.print("Error: Could not save vault\n", .{});
                return;
            };
            std.debug.print("TOTP entry '{s}' deleted.\n", .{entry_name});
        },
        .password => |*p| {
            if (p.totp_secret == null) {
                std.debug.print("Entry '{s}' has no TOTP configured.\n", .{entry_name});
                return;
            }
            @memset(@constCast(p.totp_secret.?), 0);
            allocator.free(p.totp_secret.?);
            p.totp_secret = null;
            p.totp_algorithm = .sha1;
            p.totp_digits = 6;
            p.totp_period = 30;
            e.modified_at = std.time.timestamp();

            ctx.vault.save() catch {
                std.debug.print("Error: Could not save vault\n", .{});
                return;
            };
            std.debug.print("TOTP removed from '{s}'.\n", .{entry_name});
        },
        .passkey => {
            std.debug.print("Entry '{s}' is a passkey, not a TOTP entry.\n", .{entry_name});
        },
    }
}

fn runGet(allocator: std.mem.Allocator, entry_name: []const u8, cfg: config.Config) !void {
    var ctx = vault_helpers.openAndUnlock(allocator) catch return;
    defer ctx.deinit();

    const found_entry = ctx.vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    const e = found_entry.?;
    switch (e.data) {
        .totp => |t| {
            try generateAndShowCode(allocator, t.secret, t.algorithm, t.digits, t.period, cfg);
        },
        .password => |p| {
            if (p.totp_secret) |secret| {
                try generateAndShowCode(allocator, secret, p.totp_algorithm, p.totp_digits, p.totp_period, cfg);
            } else {
                std.debug.print("Entry '{s}' has no TOTP configured. Use 'zault totp add {s}' to add one.\n", .{ entry_name, entry_name });
            }
        },
        .passkey => {
            std.debug.print("Entry '{s}' is a passkey entry.\n", .{entry_name});
        },
    }
}

fn generateAndShowCode(
    allocator: std.mem.Allocator,
    secret: []const u8,
    algorithm: entry.TotpAlgorithm,
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
    for (ctx.vault.entries.items) |e| {
        if (e.entry_type == .totp) {
            count += 1;
        } else if (e.entry_type == .password and e.data.password.hasTotp()) {
            count += 1;
        }
    }

    if (count == 0) {
        std.debug.print("No TOTP entries. Use 'zault totp add <name>' to add one.\n", .{});
        return;
    }

    std.debug.print("TOTP Entries ({d}):\n", .{count});
    std.debug.print("{s:<30} {s:<12} {s}\n", .{ "NAME", "TYPE", "ISSUER" });
    std.debug.print("{s}\n", .{"-" ** 55});

    for (ctx.vault.entries.items) |e| {
        if (e.entry_type == .totp) {
            const issuer = e.data.totp.issuer orelse "";
            std.debug.print("{s:<30} {s:<12} {s}\n", .{ e.name, "standalone", issuer });
        } else if (e.entry_type == .password and e.data.password.hasTotp()) {
            std.debug.print("{s:<30} {s:<12} {s}\n", .{ e.name, "password+", "" });
        }
    }
}

fn showHelp() void {
    const help =
        \\Usage: zault totp <subcommand> [options]
        \\
        \\Subcommands:
        \\    add <name>      Add TOTP to entry (or create standalone)
        \\    delete <name>   Remove TOTP from entry
        \\    list            List all entries with TOTP
        \\    <name>          Get current TOTP code for entry
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
