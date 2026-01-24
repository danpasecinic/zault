const std = @import("std");
const builtin = @import("builtin");

pub const ClipboardError = error{
    UnsupportedPlatform,
    CommandFailed,
    Timeout,
};

pub fn copyWithTimeout(
    allocator: std.mem.Allocator,
    text: []const u8,
    timeout_seconds: u32,
) !void {
    try copy(allocator, text);

    if (timeout_seconds > 0) {
        const clear_cmd = try getClearCommand(allocator, timeout_seconds);
        defer allocator.free(clear_cmd);

        var child = std.process.Child.init(
            &[_][]const u8{ "sh", "-c", clear_cmd },
            allocator,
        );
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        _ = child.spawn() catch {};
    }
}

pub fn copy(allocator: std.mem.Allocator, text: []const u8) !void {
    const cmd = try getCopyCommand();

    var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    try child.spawn();

    if (child.stdin) |stdin| {
        stdin.writeAll(text) catch {};
        stdin.close();
        child.stdin = null;
    }

    const result = child.wait() catch return ClipboardError.CommandFailed;

    if (result.Exited != 0) {
        return ClipboardError.CommandFailed;
    }
}

pub fn clear(allocator: std.mem.Allocator) !void {
    try copy(allocator, "");
}

fn getCopyCommand() ![]const u8 {
    return switch (builtin.os.tag) {
        .macos => "pbcopy",
        .linux => blk: {
            if (std.posix.getenv("WAYLAND_DISPLAY") != null) {
                break :blk "wl-copy";
            } else {
                break :blk "xclip -selection clipboard";
            }
        },
        else => return ClipboardError.UnsupportedPlatform,
    };
}

fn getClearCommand(allocator: std.mem.Allocator, timeout_seconds: u32) ![]u8 {
    const copy_cmd = try getCopyCommand();

    return switch (builtin.os.tag) {
        .macos => std.fmt.allocPrint(
            allocator,
            "sleep {d} && echo -n '' | {s}",
            .{ timeout_seconds, copy_cmd },
        ),
        .linux => blk: {
            if (std.posix.getenv("WAYLAND_DISPLAY") != null) {
                break :blk std.fmt.allocPrint(
                    allocator,
                    "sleep {d} && wl-copy ''",
                    .{timeout_seconds},
                );
            } else {
                break :blk std.fmt.allocPrint(
                    allocator,
                    "sleep {d} && echo -n '' | xclip -selection clipboard",
                    .{timeout_seconds},
                );
            }
        },
        else => return ClipboardError.UnsupportedPlatform,
    };
}

pub fn isAvailable() bool {
    return switch (builtin.os.tag) {
        .macos => true,
        .linux => blk: {
            if (std.posix.getenv("WAYLAND_DISPLAY") != null) {
                break :blk checkCommand("wl-copy");
            } else {
                break :blk checkCommand("xclip");
            }
        },
        else => false,
    };
}

fn checkCommand(cmd: []const u8) bool {
    var child = std.process.Child.init(
        &[_][]const u8{ "which", cmd },
        std.heap.page_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch return false;
    const result = child.wait() catch return false;

    return result.Exited == 0;
}

test "clipboard availability check" {
    _ = isAvailable();
}
