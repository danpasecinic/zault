const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const cli = @import("cli/root.zig");
const core = @import("core/vault.zig");
const config = @import("core/config.zig");
const entry = @import("core/entry.zig");
const memory = @import("memory/secure_allocator.zig");
const argon2 = @import("crypto/argon2.zig");
const xchacha = @import("crypto/xchacha.zig");
const totp = @import("services/totp.zig");
const generator = @import("services/generator.zig");
const clipboard = @import("services/clipboard.zig");

pub const std_options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cfg = config.Config.load(allocator) catch config.Config{};

    if (try core.checkLegacyVaultExists(allocator)) {
        std.debug.print("Note: Found vault at legacy location (~/.config/zault/vault.zault).\n", .{});
        std.debug.print("Consider migrating to ~/.local/share/zault/vault.zault\n\n", .{});
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try showHelp();
        return;
    }

    const command = args[1];
    try runCommand(allocator, cfg, command, args[2..]);
}

fn runCommand(allocator: std.mem.Allocator, cfg: config.Config, command: []const u8, args: []const []const u8) !void {
    _ = allocator;
    _ = cfg;
    _ = args;

    if (std.mem.eql(u8, command, "init")) {
        try cmdInit();
    } else if (std.mem.eql(u8, command, "add")) {
        try cmdAdd();
    } else if (std.mem.eql(u8, command, "get")) {
        try cmdGet();
    } else if (std.mem.eql(u8, command, "list")) {
        try cmdList();
    } else if (std.mem.eql(u8, command, "delete")) {
        try cmdDelete();
    } else if (std.mem.eql(u8, command, "generate")) {
        try cmdGenerate();
    } else if (std.mem.eql(u8, command, "totp")) {
        try cmdTotp();
    } else if (std.mem.eql(u8, command, "passkey")) {
        try cmdPasskey();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try showHelp();
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        try showVersion();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        std.debug.print("Run 'zault help' for usage information.\n", .{});
    }
}

fn cmdInit() !void {
    std.debug.print("Initializing new vault...\n", .{});
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdAdd() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdGet() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdList() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdDelete() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdGenerate() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdTotp() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdPasskey() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn showHelp() !void {
    const help =
        \\zault - A secure credential manager
        \\
        \\USAGE:
        \\    zault [command] [options]
        \\
        \\COMMANDS:
        \\    init              Create a new vault
        \\    add <name>        Add a new credential
        \\    get <name>        Retrieve a credential (copies to clipboard)
        \\    list              List all entries
        \\    delete <name>     Remove an entry
        \\    generate          Generate a secure password
        \\    totp <subcommand> TOTP operations (add, list, get)
        \\    passkey <subcmd>  Passkey operations (list, delete)
        \\    help              Show this help message
        \\    version           Show version information
        \\
        \\OPTIONS:
        \\    -h, --help        Show help for a command
        \\    -v, --version     Show version
        \\
        \\EXAMPLES:
        \\    zault init
        \\    zault add github.com -u myuser
        \\    zault get github.com
        \\    zault totp add github.com
        \\    zault totp github.com
        \\
        \\For more information, visit: https://github.com/danpasecinic/zault
        \\
    ;
    std.debug.print("{s}", .{help});
}

fn showVersion() !void {
    std.debug.print("zault version {s}\n", .{build_options.version});
}

test "basic command parsing" {
    try showVersion();
}

test {
    @import("std").testing.refAllDecls(@This());
    _ = cli;
    _ = core;
    _ = config;
    _ = entry;
    _ = memory;
    _ = argon2;
    _ = xchacha;
    _ = totp;
    _ = generator;
    _ = clipboard;
}
