const std = @import("std");

pub const GeneratorOptions = struct {
    length: u32 = 20,
    uppercase: bool = true,
    lowercase: bool = true,
    digits: bool = true,
    symbols: bool = true,
    exclude_ambiguous: bool = true,
    custom_symbols: ?[]const u8 = null,
};

const default_symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const ambiguous_chars = "0O1lI";

pub fn generate(allocator: std.mem.Allocator, options: GeneratorOptions) ![]u8 {
    var charset: std.ArrayList(u8) = .empty;
    defer charset.deinit(allocator);

    if (options.uppercase) {
        for ("ABCDEFGHIJKLMNOPQRSTUVWXYZ") |c| {
            if (!options.exclude_ambiguous or !isAmbiguous(c)) {
                try charset.append(allocator, c);
            }
        }
    }

    if (options.lowercase) {
        for ("abcdefghijklmnopqrstuvwxyz") |c| {
            if (!options.exclude_ambiguous or !isAmbiguous(c)) {
                try charset.append(allocator, c);
            }
        }
    }

    if (options.digits) {
        for ("0123456789") |c| {
            if (!options.exclude_ambiguous or !isAmbiguous(c)) {
                try charset.append(allocator, c);
            }
        }
    }

    if (options.symbols) {
        const symbols = options.custom_symbols orelse default_symbols;
        for (symbols) |c| {
            try charset.append(allocator, c);
        }
    }

    if (charset.items.len == 0) {
        return error.EmptyCharset;
    }

    const password = try allocator.alloc(u8, options.length);
    errdefer allocator.free(password);

    std.crypto.random.bytes(password);

    for (password) |*c| {
        c.* = charset.items[c.* % charset.items.len];
    }

    try ensureCharacterCategories(password, options, charset.items);

    return password;
}

fn isAmbiguous(c: u8) bool {
    for (ambiguous_chars) |ac| {
        if (c == ac) return true;
    }
    return false;
}

fn ensureCharacterCategories(password: []u8, options: GeneratorOptions, charset: []const u8) !void {
    _ = charset;

    if (password.len < 4) return;

    var positions: [4]usize = .{ 0, 1, 2, 3 };

    var rng = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
    const random = rng.random();

    for (0..positions.len) |i| {
        const j = random.intRangeAtMost(usize, i, positions.len - 1);
        const tmp = positions[i];
        positions[i] = positions[j];
        positions[j] = tmp;
    }

    var pos_idx: usize = 0;

    if (options.uppercase and pos_idx < positions.len) {
        const chars = if (options.exclude_ambiguous) "ABCDEFGHJKMNPQRSTUVWXYZ" else "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        password[positions[pos_idx]] = chars[random.intRangeLessThan(usize, 0, chars.len)];
        pos_idx += 1;
    }

    if (options.lowercase and pos_idx < positions.len) {
        const chars = if (options.exclude_ambiguous) "abcdefghjkmnpqrstuvwxyz" else "abcdefghijklmnopqrstuvwxyz";
        password[positions[pos_idx]] = chars[random.intRangeLessThan(usize, 0, chars.len)];
        pos_idx += 1;
    }

    if (options.digits and pos_idx < positions.len) {
        const chars = if (options.exclude_ambiguous) "23456789" else "0123456789";
        password[positions[pos_idx]] = chars[random.intRangeLessThan(usize, 0, chars.len)];
        pos_idx += 1;
    }

    if (options.symbols and pos_idx < positions.len) {
        const chars = options.custom_symbols orelse default_symbols;
        password[positions[pos_idx]] = chars[random.intRangeLessThan(usize, 0, chars.len)];
        pos_idx += 1;
    }
}

pub fn generatePassphrase(
    allocator: std.mem.Allocator,
    word_count: u32,
    separator: u8,
) ![]u8 {
    const words = [_][]const u8{
        "apple",    "banana", "cherry",   "dragon", "eagle",
        "falcon",   "garden", "hammer",   "island", "jungle",
        "kettle",   "lemon",  "mountain", "nebula", "ocean",
        "planet",   "quartz", "river",    "sunset", "tiger",
        "umbrella", "violet", "whisper",  "xenon",  "yellow",
        "zebra",    "anchor", "beacon",   "castle", "diamond",
    };

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (0..word_count) |i| {
        if (i > 0) {
            try result.append(allocator, separator);
        }

        var random_bytes: [1]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const word_idx = random_bytes[0] % words.len;

        try result.appendSlice(allocator, words[word_idx]);
    }

    return result.toOwnedSlice(allocator);
}

pub fn calculateEntropy(password: []const u8) f64 {
    var charset_size: u32 = 0;
    var has_lower = false;
    var has_upper = false;
    var has_digit = false;
    var has_symbol = false;

    for (password) |c| {
        if (std.ascii.isLower(c)) has_lower = true;
        if (std.ascii.isUpper(c)) has_upper = true;
        if (std.ascii.isDigit(c)) has_digit = true;
        if (!std.ascii.isAlphanumeric(c)) has_symbol = true;
    }

    if (has_lower) charset_size += 26;
    if (has_upper) charset_size += 26;
    if (has_digit) charset_size += 10;
    if (has_symbol) charset_size += 32;

    if (charset_size == 0) return 0;

    const len: f64 = @floatFromInt(password.len);
    const size: f64 = @floatFromInt(charset_size);

    return len * @log2(size);
}

test "generate password" {
    const allocator = std.testing.allocator;

    const password = try generate(allocator, .{ .length = 16 });
    defer allocator.free(password);

    try std.testing.expectEqual(@as(usize, 16), password.len);
}

test "generate passphrase" {
    const allocator = std.testing.allocator;

    const passphrase = try generatePassphrase(allocator, 4, '-');
    defer allocator.free(passphrase);

    var separator_count: usize = 0;
    for (passphrase) |c| {
        if (c == '-') separator_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), separator_count);
}

test "calculate entropy" {
    const entropy = calculateEntropy("password");
    try std.testing.expect(entropy > 37 and entropy < 38);
}
