const std = @import("std");
const builtin = @import("builtin");

const cli = @import("cli/root.zig");
const core = @import("core/vault.zig");
const memory = @import("memory/secure_allocator.zig");

pub const std_options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        // No arguments - launch TUI or show help
        try showHelp();
        return;
    }

    const command = args[1];
    try runCommand(allocator, command, args[2..]);
}

fn runCommand(allocator: std.mem.Allocator, command: []const u8, args: []const []const u8) !void {
    _ = allocator;
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
    std.debug.print("zault version 0.1.0\n", .{});
}

test "basic command parsing" {
    // Basic smoke test
    try showVersion();
}
