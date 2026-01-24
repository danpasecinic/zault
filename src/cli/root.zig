const std = @import("std");

pub const Command = enum {
    init,
    add,
    get,
    list,
    delete,
    generate,
    totp,
    passkey,
    help,
    version,
};

pub const Args = struct {
    command: Command,
    positional: []const []const u8,
    username: ?[]const u8 = null,
    output_format: OutputFormat = .text,
    clipboard: bool = true,
    timeout: u32 = 45,
};

pub const OutputFormat = enum {
    text,
    json,
};

pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Args {
    _ = allocator;

    if (args.len == 0) {
        return Args{
            .command = .help,
            .positional = &[_][]const u8{},
        };
    }

    const cmd_str = args[0];
    const command = parseCommand(cmd_str) orelse {
        std.debug.print("Unknown command: {s}\n", .{cmd_str});
        return Args{
            .command = .help,
            .positional = &[_][]const u8{},
        };
    };

    return Args{
        .command = command,
        .positional = if (args.len > 1) args[1..] else &[_][]const u8{},
    };
}

fn parseCommand(cmd: []const u8) ?Command {
    const commands = .{
        .{ "init", Command.init },
        .{ "add", Command.add },
        .{ "get", Command.get },
        .{ "list", Command.list },
        .{ "ls", Command.list },
        .{ "delete", Command.delete },
        .{ "rm", Command.delete },
        .{ "generate", Command.generate },
        .{ "gen", Command.generate },
        .{ "totp", Command.totp },
        .{ "passkey", Command.passkey },
        .{ "help", Command.help },
        .{ "--help", Command.help },
        .{ "-h", Command.help },
        .{ "version", Command.version },
        .{ "--version", Command.version },
        .{ "-v", Command.version },
    };

    inline for (commands) |entry| {
        if (std.mem.eql(u8, cmd, entry[0])) {
            return entry[1];
        }
    }

    return null;
}

test "parse init command" {
    const args = parse(std.testing.allocator, &[_][]const u8{"init"}) catch unreachable;
    try std.testing.expectEqual(Command.init, args.command);
}

test "parse help aliases" {
    const args1 = parse(std.testing.allocator, &[_][]const u8{"help"}) catch unreachable;
    try std.testing.expectEqual(Command.help, args1.command);

    const args2 = parse(std.testing.allocator, &[_][]const u8{"--help"}) catch unreachable;
    try std.testing.expectEqual(Command.help, args2.command);

    const args3 = parse(std.testing.allocator, &[_][]const u8{"-h"}) catch unreachable;
    try std.testing.expectEqual(Command.help, args3.command);
}
