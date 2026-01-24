const std = @import("std");
const entry = @import("entry.zig");

pub const SerializeError = error{
    BufferTooSmall,
    OutOfMemory,
    InvalidData,
};

pub const DeserializeError = error{
    InvalidData,
    UnexpectedEndOfData,
    InvalidEntryType,
    OutOfMemory,
};

pub fn serializeEntries(allocator: std.mem.Allocator, entries: []const entry.Entry) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);

    var writer = buffer.writer(allocator);

    try writer.writeInt(u32, @intCast(entries.len), .little);

    for (entries) |e| {
        try serializeEntry(allocator, &buffer, e);
    }

    return buffer.toOwnedSlice(allocator);
}

fn serializeEntry(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), e: entry.Entry) !void {
    var writer = buffer.writer(allocator);

    try writeString(allocator, buffer, e.name);
    try writer.writeByte(@intFromEnum(e.entry_type));
    try writer.writeInt(i64, e.created_at, .little);
    try writer.writeInt(i64, e.modified_at, .little);

    switch (e.data) {
        .password => |p| {
            try writeOptionalString(allocator, buffer, p.username);
            try writeString(allocator, buffer, p.password);
            try writeOptionalString(allocator, buffer, p.url);
            try writeOptionalString(allocator, buffer, p.notes);
        },
        .totp => |t| {
            try writeString(allocator, buffer, t.secret);
            try writer.writeByte(@intFromEnum(t.algorithm));
            try writer.writeByte(t.digits);
            try writer.writeInt(u32, t.period, .little);
            try writeOptionalString(allocator, buffer, t.issuer);
        },
        .passkey => |pk| {
            try writeString(allocator, buffer, pk.credential_id);
            try writeString(allocator, buffer, pk.private_key);
            try writeString(allocator, buffer, pk.public_key);
            try writer.writeInt(i32, @intFromEnum(pk.algorithm), .little);
            try writeString(allocator, buffer, pk.rp_id);
            try writeOptionalString(allocator, buffer, pk.rp_name);
            try writeString(allocator, buffer, pk.user_handle);
            try writeOptionalString(allocator, buffer, pk.user_name);
            try writer.writeInt(u32, pk.counter, .little);
        },
    }
}

fn writeString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: []const u8) !void {
    var writer = buffer.writer(allocator);
    try writer.writeInt(u32, @intCast(s.len), .little);
    try buffer.appendSlice(allocator, s);
}

fn writeOptionalString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: ?[]const u8) !void {
    var writer = buffer.writer(allocator);
    if (s) |str| {
        try writer.writeByte(1);
        try writeString(allocator, buffer, str);
    } else {
        try writer.writeByte(0);
    }
}

pub fn deserializeEntries(allocator: std.mem.Allocator, data: []const u8) ![]entry.Entry {
    var stream = std.io.fixedBufferStream(data);
    var reader = stream.reader();

    const count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    var entries: std.ArrayList(entry.Entry) = .empty;
    errdefer {
        for (entries.items) |*e| {
            e.deinit(allocator);
        }
        entries.deinit(allocator);
    }

    for (0..count) |_| {
        const e = try deserializeEntry(allocator, &reader);
        try entries.append(allocator, e);
    }

    return entries.toOwnedSlice(allocator);
}

fn deserializeEntry(allocator: std.mem.Allocator, reader: anytype) !entry.Entry {
    const name = try readString(allocator, reader);
    errdefer allocator.free(name);

    const entry_type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const entry_type = std.meta.intToEnum(entry.EntryType, entry_type_byte) catch return DeserializeError.InvalidEntryType;

    const created_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    const modified_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;

    const data: entry.EntryData = switch (entry_type) {
        .password => .{ .password = try deserializePasswordEntry(allocator, reader) },
        .totp => .{ .totp = try deserializeTotpEntry(allocator, reader) },
        .passkey => .{ .passkey = try deserializePasskeyEntry(allocator, reader) },
    };

    return entry.Entry{
        .name = name,
        .entry_type = entry_type,
        .created_at = created_at,
        .modified_at = modified_at,
        .data = data,
    };
}

fn deserializePasswordEntry(allocator: std.mem.Allocator, reader: anytype) !entry.PasswordEntry {
    const username = try readOptionalString(allocator, reader);
    errdefer if (username) |u| allocator.free(u);

    const password = try readString(allocator, reader);
    errdefer allocator.free(password);

    const url = try readOptionalString(allocator, reader);
    errdefer if (url) |u| allocator.free(u);

    const notes = try readOptionalString(allocator, reader);
    errdefer if (notes) |n| allocator.free(n);

    return entry.PasswordEntry{
        .username = username,
        .password = password,
        .url = url,
        .notes = notes,
    };
}

fn deserializeTotpEntry(allocator: std.mem.Allocator, reader: anytype) !entry.TotpEntry {
    const secret = try readString(allocator, reader);
    errdefer allocator.free(secret);

    const algo_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const algorithm = std.meta.intToEnum(entry.TotpAlgorithm, algo_byte) catch return DeserializeError.InvalidData;

    const digits = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const period = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    const issuer = try readOptionalString(allocator, reader);
    errdefer if (issuer) |i| allocator.free(i);

    return entry.TotpEntry{
        .secret = secret,
        .algorithm = algorithm,
        .digits = digits,
        .period = period,
        .issuer = issuer,
    };
}

fn deserializePasskeyEntry(allocator: std.mem.Allocator, reader: anytype) !entry.PasskeyEntry {
    const credential_id = try readString(allocator, reader);
    errdefer allocator.free(credential_id);

    const private_key = try readString(allocator, reader);
    errdefer allocator.free(private_key);

    const public_key = try readString(allocator, reader);
    errdefer allocator.free(public_key);

    const algo_int = reader.readInt(i32, .little) catch return DeserializeError.UnexpectedEndOfData;
    const algorithm = std.meta.intToEnum(entry.PasskeyAlgorithm, algo_int) catch return DeserializeError.InvalidData;

    const rp_id = try readString(allocator, reader);
    errdefer allocator.free(rp_id);

    const rp_name = try readOptionalString(allocator, reader);
    errdefer if (rp_name) |n| allocator.free(n);

    const user_handle = try readString(allocator, reader);
    errdefer allocator.free(user_handle);

    const user_name = try readOptionalString(allocator, reader);
    errdefer if (user_name) |n| allocator.free(n);

    const counter = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    return entry.PasskeyEntry{
        .credential_id = credential_id,
        .private_key = private_key,
        .public_key = public_key,
        .algorithm = algorithm,
        .rp_id = rp_id,
        .rp_name = rp_name,
        .user_handle = user_handle,
        .user_name = user_name,
        .counter = counter,
    };
}

fn readString(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    const len = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    if (len > 1024 * 1024) {
        return DeserializeError.InvalidData;
    }

    const str = try allocator.alloc(u8, len);
    errdefer allocator.free(str);

    const bytes_read = reader.readAll(str) catch return DeserializeError.UnexpectedEndOfData;
    if (bytes_read != len) {
        return DeserializeError.UnexpectedEndOfData;
    }

    return str;
}

fn readOptionalString(allocator: std.mem.Allocator, reader: anytype) !?[]u8 {
    const present = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;

    if (present == 1) {
        return try readString(allocator, reader);
    }

    return null;
}

test "serialize and deserialize password entry" {
    const allocator = std.testing.allocator;

    var entries_list: std.ArrayList(entry.Entry) = .empty;
    defer {
        for (entries_list.items) |*ent| ent.deinit(allocator);
        entries_list.deinit(allocator);
    }

    const e = try entry.createPasswordEntry(
        allocator,
        "github.com",
        "testuser",
        "secretpassword",
        "https://github.com",
    );

    try entries_list.append(allocator, e);

    const serialized = try serializeEntries(allocator, entries_list.items);
    defer allocator.free(serialized);

    const deserialized = try deserializeEntries(allocator, serialized);
    defer {
        for (deserialized) |*de| {
            de.deinit(allocator);
        }
        allocator.free(deserialized);
    }

    try std.testing.expectEqual(@as(usize, 1), deserialized.len);
    try std.testing.expectEqualStrings("github.com", deserialized[0].name);
    try std.testing.expectEqual(entry.EntryType.password, deserialized[0].entry_type);

    const pwd = deserialized[0].data.password;
    try std.testing.expectEqualStrings("testuser", pwd.username.?);
    try std.testing.expectEqualStrings("secretpassword", pwd.password);
    try std.testing.expectEqualStrings("https://github.com", pwd.url.?);
}

test "serialize and deserialize multiple entries" {
    const allocator = std.testing.allocator;

    var entries_list: std.ArrayList(entry.Entry) = .empty;
    defer {
        for (entries_list.items) |*ent| ent.deinit(allocator);
        entries_list.deinit(allocator);
    }

    const e1 = try entry.createPasswordEntry(allocator, "site1.com", "user1", "pass1", null);
    try entries_list.append(allocator, e1);

    const e2 = try entry.createPasswordEntry(allocator, "site2.com", null, "pass2", "https://site2.com");
    try entries_list.append(allocator, e2);

    const serialized = try serializeEntries(allocator, entries_list.items);
    defer allocator.free(serialized);

    const deserialized = try deserializeEntries(allocator, serialized);
    defer {
        for (deserialized) |*de| {
            de.deinit(allocator);
        }
        allocator.free(deserialized);
    }

    try std.testing.expectEqual(@as(usize, 2), deserialized.len);
    try std.testing.expectEqualStrings("site1.com", deserialized[0].name);
    try std.testing.expectEqualStrings("site2.com", deserialized[1].name);
    try std.testing.expect(deserialized[1].data.password.username == null);
}

test "serialize empty entries" {
    const allocator = std.testing.allocator;

    var entries_list: [0]entry.Entry = .{};

    const serialized = try serializeEntries(allocator, &entries_list);
    defer allocator.free(serialized);

    const deserialized = try deserializeEntries(allocator, serialized);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(@as(usize, 0), deserialized.len);
}
