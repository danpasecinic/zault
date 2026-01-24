const std = @import("std");
const builtin = @import("builtin");

pub const TerminalError = error{
    NotATty,
    TermiosError,
    ReadError,
    BufferTooSmall,
};

pub fn readPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    stdout.writeAll(prompt) catch return TerminalError.ReadError;

    if (builtin.os.tag == .windows) {
        return readLineSimple(allocator, stdin);
    }

    if (!std.posix.isatty(stdin.handle)) {
        return readLineSimple(allocator, stdin);
    }

    const original_termios = std.posix.tcgetattr(stdin.handle) catch return TerminalError.TermiosError;

    var noecho_termios = original_termios;
    noecho_termios.lflag.ECHO = false;

    std.posix.tcsetattr(stdin.handle, .FLUSH, noecho_termios) catch return TerminalError.TermiosError;
    defer {
        std.posix.tcsetattr(stdin.handle, .FLUSH, original_termios) catch {};
        stdout.writeAll("\n") catch {};
    }

    return readLineSimple(allocator, stdin);
}

fn readLineSimple(allocator: std.mem.Allocator, file: std.fs.File) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    var buf: [1]u8 = undefined;

    while (true) {
        const bytes_read = file.read(&buf) catch return TerminalError.ReadError;
        if (bytes_read == 0) break;

        const byte = buf[0];
        if (byte == '\n' or byte == '\r') break;

        try list.append(allocator, byte);

        if (list.items.len > 1024) {
            return TerminalError.BufferTooSmall;
        }
    }

    return list.toOwnedSlice(allocator);
}

pub fn readLine(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    stdout.writeAll(prompt) catch return TerminalError.ReadError;
    return readLineSimple(allocator, stdin);
}

pub fn confirm(prompt: []const u8) !bool {
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    const stdin = std.fs.File{ .handle = std.posix.STDIN_FILENO };

    stdout.writeAll(prompt) catch return TerminalError.ReadError;
    stdout.writeAll(" [y/N]: ") catch return TerminalError.ReadError;

    var buf: [1]u8 = undefined;
    const bytes_read = stdin.read(&buf) catch return false;

    if (bytes_read == 0) return false;

    var discard: [16]u8 = undefined;
    _ = stdin.read(&discard) catch {};

    return buf[0] == 'y' or buf[0] == 'Y';
}
