const std = @import("std");

pub const Uuid = struct {
    bytes: [16]u8,

    pub fn generate() Uuid {
        var bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&bytes);
        // Set version 4 (random) and variant bits
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        return .{ .bytes = bytes };
    }

    pub fn fromBytes(bytes: [16]u8) Uuid {
        return .{ .bytes = bytes };
    }

    pub fn eql(self: Uuid, other: Uuid) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn isZero(self: Uuid) bool {
        return std.mem.eql(u8, &self.bytes, &[_]u8{0} ** 16);
    }

    pub const zero = Uuid{ .bytes = [_]u8{0} ** 16 };
};

test "uuid generate produces unique values" {
    const a = Uuid.generate();
    const b = Uuid.generate();
    try std.testing.expect(!a.eql(b));
}

test "uuid zero check" {
    const z = Uuid.zero;
    try std.testing.expect(z.isZero());

    const g = Uuid.generate();
    try std.testing.expect(!g.isZero());
}

test "uuid version 4 format" {
    const u = Uuid.generate();
    // Version should be 4
    try std.testing.expectEqual(@as(u8, 4), (u.bytes[6] >> 4) & 0x0f);
    // Variant should be 10xx
    try std.testing.expectEqual(@as(u8, 2), (u.bytes[8] >> 6) & 0x03);
}
