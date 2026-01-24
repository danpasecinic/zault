const std = @import("std");

pub const TotpError = error{
    InvalidSecret,
    InvalidAlgorithm,
    Base32DecodeError,
};

pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,
};

// RFC 6238
pub fn generate(
    secret: []const u8,
    time: i64,
    period: u32,
    digits: u8,
    algorithm: Algorithm,
) !u32 {
    const decoded_secret = try base32Decode(std.heap.page_allocator, secret);
    defer {
        @memset(decoded_secret, 0);
        std.heap.page_allocator.free(decoded_secret);
    }

    const counter: u64 = @intCast(@divFloor(time, period));

    return hotp(decoded_secret, counter, digits, algorithm);
}

pub fn generateCurrent(
    secret: []const u8,
    period: u32,
    digits: u8,
    algorithm: Algorithm,
) !u32 {
    const now = std.time.timestamp();
    return generate(secret, now, period, digits, algorithm);
}

pub fn getTimeRemaining(period: u32) u32 {
    const now: u64 = @intCast(std.time.timestamp());
    return period - @as(u32, @intCast(now % period));
}

// RFC 4226
fn hotp(secret: []const u8, counter: u64, digits: u8, algorithm: Algorithm) u32 {
    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_bytes, counter, .big);

    var hmac_result: [64]u8 = undefined;
    defer @memset(&hmac_result, 0);
    var hmac_len: usize = 0;

    switch (algorithm) {
        .sha1 => {
            const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
            var hmac = HmacSha1.init(secret);
            hmac.update(&counter_bytes);
            var result: [HmacSha1.mac_length]u8 = undefined;
            hmac.final(&result);
            @memcpy(hmac_result[0..result.len], &result);
            hmac_len = result.len;
        },
        .sha256 => {
            const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
            var hmac = HmacSha256.init(secret);
            hmac.update(&counter_bytes);
            var result: [HmacSha256.mac_length]u8 = undefined;
            hmac.final(&result);
            @memcpy(hmac_result[0..result.len], &result);
            hmac_len = result.len;
        },
        .sha512 => {
            const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
            var hmac = HmacSha512.init(secret);
            hmac.update(&counter_bytes);
            var result: [HmacSha512.mac_length]u8 = undefined;
            hmac.final(&result);
            @memcpy(hmac_result[0..result.len], &result);
            hmac_len = result.len;
        },
    }

    const offset: usize = hmac_result[hmac_len - 1] & 0x0F;
    const binary: u32 = (@as(u32, hmac_result[offset] & 0x7F) << 24) |
        (@as(u32, hmac_result[offset + 1]) << 16) |
        (@as(u32, hmac_result[offset + 2]) << 8) |
        @as(u32, hmac_result[offset + 3]);

    var modulo: u32 = 1;
    for (0..digits) |_| {
        modulo *= 10;
    }

    return binary % modulo;
}

pub const TotpParams = struct {
    secret: []const u8,
    issuer: ?[]const u8,
    account: ?[]const u8,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
};

pub fn parseUri(allocator: std.mem.Allocator, uri: []const u8) !TotpParams {
    _ = allocator;

    if (!std.mem.startsWith(u8, uri, "otpauth://totp/")) {
        return TotpError.InvalidSecret;
    }

    return TotpParams{
        .secret = "",
        .issuer = null,
        .account = null,
        .algorithm = .sha1,
        .digits = 6,
        .period = 30,
    };
}

pub fn generateUri(
    allocator: std.mem.Allocator,
    secret: []const u8,
    issuer: []const u8,
    account: []const u8,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
) ![]const u8 {
    const algo_str = switch (algorithm) {
        .sha1 => "SHA1",
        .sha256 => "SHA256",
        .sha512 => "SHA512",
    };

    return std.fmt.allocPrint(
        allocator,
        "otpauth://totp/{s}:{s}?secret={s}&issuer={s}&algorithm={s}&digits={d}&period={d}",
        .{ issuer, account, secret, issuer, algo_str, digits, period },
    );
}

const base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32Decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var clean_len: usize = 0;
    for (input) |c| {
        if (c != '=' and c != ' ' and c != '\n' and c != '\r') {
            clean_len += 1;
        }
    }

    if (clean_len == 0) {
        return TotpError.Base32DecodeError;
    }

    const output_len = (clean_len * 5) / 8;
    const output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var buffer: u64 = 0;
    var bits_in_buffer: u32 = 0;
    var output_idx: usize = 0;

    for (input) |c| {
        if (c == '=' or c == ' ' or c == '\n' or c == '\r') continue;

        const upper_c = std.ascii.toUpper(c);
        const value = for (base32_alphabet, 0..) |ac, i| {
            if (ac == upper_c) break @as(u64, @intCast(i));
        } else {
            return TotpError.Base32DecodeError;
        };

        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            output[output_idx] = @intCast((buffer >> @intCast(bits_in_buffer)) & 0xFF);
            output_idx += 1;
        }
    }

    return output[0..output_idx];
}

test "base32 decode" {
    const allocator = std.testing.allocator;

    const decoded = try base32Decode(allocator, "JBSWY3DPEE");
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("Hello!", decoded);
}

test "hotp generation" {
    const secret = "12345678901234567890";

    try std.testing.expectEqual(@as(u32, 755224), hotp(secret, 0, 6, .sha1));
    try std.testing.expectEqual(@as(u32, 287082), hotp(secret, 1, 6, .sha1));
    try std.testing.expectEqual(@as(u32, 359152), hotp(secret, 2, 6, .sha1));
}
