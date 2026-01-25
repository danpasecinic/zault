const std = @import("std");
const config = @import("../../core/config.zig");
const agent = @import("../../services/agent.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, _: config.Config) !void {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            showHelp();
            return;
        }
    }

    var client = agent.AgentClient.init(allocator) catch {
        std.debug.print("Error: Could not initialize agent client\n", .{});
        return;
    };
    defer client.deinit();

    if (!client.isAgentRunning()) {
        std.debug.print("Vault is not unlocked (no agent running).\n", .{});
        return;
    }

    client.lock() catch {
        std.debug.print("Error: Could not lock vault\n", .{});
        return;
    };

    std.debug.print("Vault locked.\n", .{});
}

fn showHelp() void {
    const help =
        \\Usage: zault lock
        \\
        \\Lock the vault by stopping the agent. This securely erases the
        \\encryption key from memory.
        \\
        \\Options:
        \\    -h, --help    Show this help message
        \\
        \\Examples:
        \\    zault lock
        \\
    ;
    std.debug.print("{s}", .{help});
}
