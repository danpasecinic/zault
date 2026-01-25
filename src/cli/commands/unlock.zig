const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");
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

    if (client.isAgentRunning()) {
        std.debug.print("Vault is already unlocked.\n", .{});
        return;
    }

    const foreground = for (args) |arg| {
        if (std.mem.eql(u8, arg, "--foreground") or std.mem.eql(u8, arg, "-f")) {
            break true;
        }
    } else false;

    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
            },
        }
        return;
    };
    defer vault.deinit();

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
            },
        }
        return;
    };

    const derived_key = vault.derived_key orelse {
        std.debug.print("Error: No derived key available\n", .{});
        return;
    };

    var server = agent.AgentServer.init(allocator, derived_key) catch {
        std.debug.print("Error: Could not initialize agent server\n", .{});
        return;
    };

    server.start() catch |err| {
        server.deinit();
        switch (err) {
            agent.AgentError.BindFailed => {
                std.debug.print("Error: Could not bind socket (agent may already be running)\n", .{});
            },
            else => {
                std.debug.print("Error: Could not start agent\n", .{});
            },
        }
        return;
    };

    std.debug.print("Vault unlocked. Agent running.\n", .{});

    if (foreground) {
        std.debug.print("Press Ctrl+C to lock and exit.\n", .{});
        server.runLoop();
        server.deinit();
        std.debug.print("Agent stopped. Vault locked.\n", .{});
    } else {
        const pid = std.posix.fork() catch {
            std.debug.print("Error: Could not fork agent process\n", .{});
            server.deinit();
            return;
        };

        if (pid == 0) {
            _ = std.posix.setsid() catch {};
            std.posix.close(std.posix.STDIN_FILENO);
            std.posix.close(std.posix.STDOUT_FILENO);
            std.posix.close(std.posix.STDERR_FILENO);
            server.runLoop();
            server.deinit();
            std.posix.exit(0);
        } else {
            server.server = null;
            server.deinit();
            std.debug.print("Agent running in background (PID: {d}).\n", .{pid});
            std.debug.print("Run 'zault lock' to lock the vault.\n", .{});
        }
    }
}

fn showHelp() void {
    const help =
        \\Usage: zault unlock [options]
        \\
        \\Unlock the vault and start the agent. The agent holds the derived
        \\encryption key in memory, so subsequent commands don't require
        \\entering the master password.
        \\
        \\Options:
        \\    -f, --foreground    Run agent in foreground (don't daemonize)
        \\    -h, --help          Show this help message
        \\
        \\Examples:
        \\    zault unlock                # Start agent in background
        \\    zault unlock --foreground   # Run in foreground (Ctrl+C to lock)
        \\
    ;
    std.debug.print("{s}", .{help});
}
