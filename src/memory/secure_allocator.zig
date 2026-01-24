const std = @import("std");
const builtin = @import("builtin");

pub const SecureAllocator = struct {
    backing_allocator: std.mem.Allocator,
    total_allocated: usize,
    total_locked: usize,

    const Self = @This();

    pub fn init(backing_allocator: std.mem.Allocator) Self {
        return Self{
            .backing_allocator = backing_allocator,
            .total_allocated = 0,
            .total_locked = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.total_allocated > 0) {
            std.log.warn("SecureAllocator: {d} bytes still allocated at deinit", .{self.total_allocated});
        }
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const ptr = self.backing_allocator.rawAlloc(len, ptr_align, ret_addr) orelse return null;

        if (lockMemory(ptr, len)) {
            self.total_locked += len;
        } else |_| {
            std.log.warn("Failed to lock {d} bytes of memory", .{len});
        }

        self.total_allocated += len;
        return ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));

        _ = self;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));

        secureZero(buf);
        unlockMemory(buf.ptr, buf.len) catch {};
        self.total_allocated -= buf.len;
        self.backing_allocator.rawFree(buf, buf_align, ret_addr);
    }
};

// Zeros memory using volatile writes to prevent optimization
pub fn secureZero(buf: []u8) void {
    const volatile_buf: []volatile u8 = @ptrCast(buf);
    std.crypto.secureZero(u8, volatile_buf);
}

fn lockMemory(ptr: [*]u8, len: usize) !void {
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        const result = std.c.mlock(ptr, len);
        if (result != 0) {
            return error.MlockFailed;
        }
    }
}

fn unlockMemory(ptr: [*]u8, len: usize) !void {
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        _ = std.c.munlock(ptr, len);
    }
}

pub fn Secret(comptime T: type) type {
    return struct {
        value: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return Self{ .value = value };
        }

        pub fn deinit(self: *Self) void {
            const bytes = std.mem.asBytes(&self.value);
            secureZero(bytes);
        }

        pub fn expose(self: *const Self) T {
            return self.value;
        }
    };
}

test "secure zero" {
    var buf = [_]u8{ 1, 2, 3, 4, 5 };
    secureZero(&buf);

    for (buf) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "secret wrapper" {
    var secret = Secret([4]u8).init(.{ 's', 'e', 'c', 'r' });
    defer secret.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 's', 'e', 'c', 'r' }, &secret.expose());
}
