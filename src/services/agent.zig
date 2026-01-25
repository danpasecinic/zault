const std = @import("std");
const builtin = @import("builtin");
const memory = @import("../memory/secure_allocator.zig");
const argon2 = @import("../crypto/argon2.zig");

pub const AgentError = error{
    SocketCreationFailed,
    BindFailed,
    ListenFailed,
    ConnectionFailed,
    ProtocolError,
    NotRunning,
    AlreadyRunning,
    PermissionDenied,
};

pub const Command = enum {
    get_key,
    lock,
    status,
};

pub const Response = enum {
    key,
    locked,
    unlocked,
    ok,
    err,
};

const PROTOCOL_VERSION: u8 = 1;
const KEY_LENGTH = argon2.key_length;

pub fn getSocketPath(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("XDG_RUNTIME_DIR")) |runtime_dir| {
        const dir_path = try std.fmt.allocPrint(allocator, "{s}/zault", .{runtime_dir});
        defer allocator.free(dir_path);
        std.fs.cwd().makePath(dir_path) catch {};
        return std.fmt.allocPrint(allocator, "{s}/zault/agent.sock", .{runtime_dir});
    }

    const user = std.posix.getenv("USER") orelse "unknown";
    const dir_path = try std.fmt.allocPrint(allocator, "/tmp/zault-{s}", .{user});
    defer allocator.free(dir_path);
    std.fs.cwd().makePath(dir_path) catch {};

    return std.fmt.allocPrint(allocator, "/tmp/zault-{s}/agent.sock", .{user});
}

pub const AgentServer = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    derived_key: [KEY_LENGTH]u8,
    server: ?std.posix.socket_t,
    running: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, derived_key: [KEY_LENGTH]u8) !Self {
        const socket_path = try getSocketPath(allocator);

        return Self{
            .allocator = allocator,
            .socket_path = socket_path,
            .derived_key = derived_key,
            .server = null,
            .running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        memory.secureZero(&self.derived_key);
        self.allocator.free(self.socket_path);
    }

    pub fn start(self: *Self) !void {
        std.fs.cwd().deleteFile(self.socket_path) catch {};

        const addr = std.net.Address.initUnix(self.socket_path) catch return AgentError.SocketCreationFailed;

        const socket = std.posix.socket(
            std.posix.AF.UNIX,
            std.posix.SOCK.STREAM,
            0,
        ) catch return AgentError.SocketCreationFailed;
        errdefer std.posix.close(socket);

        std.posix.bind(socket, &addr.any, addr.getOsSockLen()) catch return AgentError.BindFailed;

        if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
            if (std.posix.toPosixPath(self.socket_path)) |path_z| {
                _ = std.c.chmod(&path_z, 0o600);
            } else |_| {}
        }

        std.posix.listen(socket, 5) catch return AgentError.ListenFailed;

        self.server = socket;
        self.running = true;
    }

    pub fn runLoop(self: *Self) void {
        const server = self.server orelse return;

        while (self.running) {
            var client_addr: std.posix.sockaddr = undefined;
            var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            const client = std.posix.accept(server, &client_addr, &addr_len, 0) catch continue;
            defer std.posix.close(client);

            self.handleClient(client);
        }
    }

    fn handleClient(self: *Self, client: std.posix.socket_t) void {
        var buf: [32]u8 = undefined;
        const n = std.posix.read(client, &buf) catch return;
        if (n == 0) return;

        const cmd_line = std.mem.trimRight(u8, buf[0..n], "\n\r");

        if (std.mem.eql(u8, cmd_line, "GET_KEY")) {
            var response: [1 + KEY_LENGTH]u8 = undefined;
            response[0] = @intFromEnum(Response.key);
            @memcpy(response[1..], &self.derived_key);
            _ = std.posix.write(client, &response) catch {};
        } else if (std.mem.eql(u8, cmd_line, "LOCK")) {
            _ = std.posix.write(client, &[_]u8{@intFromEnum(Response.ok)}) catch {};
            self.running = false;
        } else if (std.mem.eql(u8, cmd_line, "STATUS")) {
            _ = std.posix.write(client, &[_]u8{@intFromEnum(Response.unlocked)}) catch {};
        } else {
            _ = std.posix.write(client, &[_]u8{@intFromEnum(Response.err)}) catch {};
        }
    }

    pub fn stop(self: *Self) void {
        self.running = false;
        if (self.server) |s| {
            std.posix.close(s);
            self.server = null;
        }
        std.fs.cwd().deleteFile(self.socket_path) catch {};
    }
};

pub const AgentClient = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        const socket_path = try getSocketPath(allocator);
        return Self{
            .allocator = allocator,
            .socket_path = socket_path,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.socket_path);
    }

    pub fn isAgentRunning(self: *Self) bool {
        std.fs.cwd().access(self.socket_path, .{}) catch return false;

        const result = self.getStatus() catch return false;
        return result;
    }

    pub fn getStatus(self: *Self) !bool {
        const socket = try self.connect();
        defer std.posix.close(socket);

        _ = std.posix.write(socket, "STATUS\n") catch return AgentError.ProtocolError;

        var buf: [1]u8 = undefined;
        const n = std.posix.read(socket, &buf) catch return AgentError.ProtocolError;
        if (n != 1) return AgentError.ProtocolError;

        const response: Response = @enumFromInt(buf[0]);
        return response == .unlocked;
    }

    pub fn getKey(self: *Self) ![KEY_LENGTH]u8 {
        const socket = try self.connect();
        defer std.posix.close(socket);

        _ = std.posix.write(socket, "GET_KEY\n") catch return AgentError.ProtocolError;

        var buf: [1 + KEY_LENGTH]u8 = undefined;
        const n = std.posix.read(socket, &buf) catch return AgentError.ProtocolError;
        if (n != 1 + KEY_LENGTH) return AgentError.ProtocolError;

        const response: Response = @enumFromInt(buf[0]);
        if (response != .key) return AgentError.ProtocolError;

        return buf[1..][0..KEY_LENGTH].*;
    }

    pub fn lock(self: *Self) !void {
        const socket = try self.connect();
        defer std.posix.close(socket);

        _ = std.posix.write(socket, "LOCK\n") catch return AgentError.ProtocolError;

        var buf: [1]u8 = undefined;
        _ = std.posix.read(socket, &buf) catch {};
    }

    fn connect(self: *Self) !std.posix.socket_t {
        const addr = std.net.Address.initUnix(self.socket_path) catch return AgentError.ConnectionFailed;

        const socket = std.posix.socket(
            std.posix.AF.UNIX,
            std.posix.SOCK.STREAM,
            0,
        ) catch return AgentError.ConnectionFailed;
        errdefer std.posix.close(socket);

        std.posix.connect(socket, &addr.any, addr.getOsSockLen()) catch return AgentError.NotRunning;

        return socket;
    }
};

test "socket path generation" {
    const allocator = std.testing.allocator;
    const path = try getSocketPath(allocator);
    defer allocator.free(path);

    try std.testing.expect(path.len > 0);
    try std.testing.expect(std.mem.endsWith(u8, path, "agent.sock"));
}
