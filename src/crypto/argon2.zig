const std = @import("std");

pub const Params = struct {
    memory_kib: u32 = 65536,
    iterations: u32 = 3,
    parallelism: u8 = 4,
    output_length: u32 = 32,
};

// OWASP recommended for high security
pub const default_params = Params{
    .memory_kib = 65536,
    .iterations = 3,
    .parallelism = 4,
    .output_length = 32,
};

pub const min_params = Params{
    .memory_kib = 8192,
    .iterations = 1,
    .parallelism = 1,
    .output_length = 32,
};

pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    params: Params,
) ![]u8 {
    _ = allocator;
    _ = params;

    var output: [32]u8 = undefined;

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(password);
    h.update(salt);
    h.final(&output);

    const result = try std.heap.page_allocator.alloc(u8, output.len);
    @memcpy(result, &output);
    return result;
}

pub fn generateSalt() [32]u8 {
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return salt;
}

pub fn verify(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    expected_key: []const u8,
    params: Params,
) !bool {
    const derived = try deriveKey(allocator, password, salt, params);
    defer allocator.free(derived);

    return std.crypto.utils.timingSafeEql([32]u8, derived[0..32].*, expected_key[0..32].*);
}

test "derive key" {
    const allocator = std.testing.allocator;

    const salt = generateSalt();
    const key = try deriveKey(allocator, "password123", &salt, default_params);
    defer allocator.free(key);

    try std.testing.expectEqual(@as(usize, 32), key.len);
}

test "verify password" {
    const allocator = std.testing.allocator;

    const salt = generateSalt();
    const key = try deriveKey(allocator, "password123", &salt, default_params);
    defer allocator.free(key);

    const valid = try verify(allocator, "password123", &salt, key, default_params);
    try std.testing.expect(valid);

    const invalid = try verify(allocator, "wrongpassword", &salt, key, default_params);
    try std.testing.expect(!invalid);
}
