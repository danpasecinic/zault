const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

pub const Params = struct {
    t: u32 = 3,
    m: u32 = 65536,
    p: u24 = 4,
};

pub const default_params = Params{
    .t = 3,
    .m = 65536,
    .p = 4,
};

pub const min_params = Params{
    .t = 1,
    .m = 8192,
    .p = 1,
};

pub const salt_length = 32;
pub const key_length = 32;

pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: *const [salt_length]u8,
    params: Params,
) ![key_length]u8 {
    var derived_key: [key_length]u8 = undefined;

    try argon2.kdf(
        allocator,
        &derived_key,
        password,
        salt,
        .{ .t = params.t, .m = params.m, .p = params.p },
        .argon2id,
    );

    return derived_key;
}

pub fn generateSalt() [salt_length]u8 {
    var salt: [salt_length]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

pub fn verify(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: *const [salt_length]u8,
    expected_key: *const [key_length]u8,
    params: Params,
) !bool {
    const derived = try deriveKey(allocator, password, salt, params);
    return std.crypto.timing_safe.eql([key_length]u8, derived, expected_key.*);
}

test "derive key" {
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    const key = try deriveKey(allocator, "password123", &salt, min_params);
    try std.testing.expectEqual(@as(usize, key_length), key.len);
}

test "verify password" {
    const allocator = std.testing.allocator;
    const salt = generateSalt();
    const key = try deriveKey(allocator, "password123", &salt, min_params);

    const valid = try verify(allocator, "password123", &salt, &key, min_params);
    try std.testing.expect(valid);

    const invalid = try verify(allocator, "wrongpassword", &salt, &key, min_params);
    try std.testing.expect(!invalid);
}

test "deterministic output" {
    const allocator = std.testing.allocator;
    const salt = [_]u8{0} ** salt_length;

    const key1 = try deriveKey(allocator, "test", &salt, min_params);
    const key2 = try deriveKey(allocator, "test", &salt, min_params);

    try std.testing.expectEqualSlices(u8, &key1, &key2);
}
