const std = @import("std");
const item = @import("item.zig");
const Uuid = @import("uuid.zig").Uuid;

pub const SerializeError = error{
    OutOfMemory,
};

pub const DeserializeError = error{
    InvalidData,
    UnexpectedEndOfData,
    InvalidItemType,
    OutOfMemory,
};

pub fn serializeItems(allocator: std.mem.Allocator, items: []const item.Item) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);

    const writer = buffer.writer(allocator);

    try writer.writeInt(u32, @intCast(items.len), .little);

    for (items) |i| {
        try serializeItem(allocator, &buffer, i);
    }

    return buffer.toOwnedSlice(allocator);
}

fn serializeItem(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), i: item.Item) !void {
    const writer = buffer.writer(allocator);

    try buffer.appendSlice(allocator, &i.id.bytes);

    try writeString(allocator, buffer, i.name);
    try writeOptionalString(allocator, buffer, i.notes);

    try writer.writeByte(@intFromEnum(i.item_type));

    try writer.writeByte(if (i.favorite) 1 else 0);

    try writer.writeInt(i64, i.created_at, .little);
    try writer.writeInt(i64, i.modified_at, .little);
    try writeOptionalI64(allocator, buffer, i.last_accessed_at);
    try writer.writeInt(u32, i.access_count, .little);
    try writeOptionalI64(allocator, buffer, i.deleted_at);

    try writer.writeInt(u32, @intCast(i.fields.len), .little);
    for (i.fields) |f| {
        try serializeCustomField(allocator, buffer, f);
    }

    try writer.writeInt(u32, @intCast(i.password_history.len), .little);
    for (i.password_history) |h| {
        try writeString(allocator, buffer, h.password);
        try writer.writeInt(i64, h.changed_at, .little);
    }

    try serializeItemData(allocator, buffer, i.data);
}

fn serializeCustomField(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), f: item.CustomField) !void {
    const writer = buffer.writer(allocator);
    try writeString(allocator, buffer, f.name);
    try writeOptionalString(allocator, buffer, f.value);
    try writer.writeByte(@intFromEnum(f.field_type));
}

fn serializeItemData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), data: item.ItemData) !void {
    switch (data) {
        .login => |l| try serializeLoginData(allocator, buffer, l),
        .secure_note => {},
        .card => |c| try serializeCardData(allocator, buffer, c),
        .identity => |i| try serializeIdentityData(allocator, buffer, i),
        .ssh_key => |s| try serializeSshKeyData(allocator, buffer, s),
        .api_credential => |a| try serializeApiCredentialData(allocator, buffer, a),
        .database => |d| try serializeDatabaseData(allocator, buffer, d),
        .wifi => |w| try serializeWifiData(allocator, buffer, w),
        .license => |l| try serializeLicenseData(allocator, buffer, l),
    }
}

fn serializeLoginData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), l: item.LoginData) !void {
    const writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, l.username);
    try writeOptionalString(allocator, buffer, l.password);

    try writer.writeInt(u32, @intCast(l.uris.len), .little);
    for (l.uris) |uri| {
        try writeString(allocator, buffer, uri.uri);
        try writer.writeByte(@intFromEnum(uri.match_type));
    }

    if (l.totp) |t| {
        try writer.writeByte(1);
        try writeString(allocator, buffer, t.secret);
        try writer.writeByte(@intFromEnum(t.algorithm));
        try writer.writeByte(t.digits);
        try writer.writeInt(u32, t.period, .little);
    } else {
        try writer.writeByte(0);
    }

    try writer.writeInt(u32, @intCast(l.passkeys.len), .little);
    for (l.passkeys) |pk| {
        try writeString(allocator, buffer, pk.credential_id);
        try writeString(allocator, buffer, pk.private_key);
        try writeString(allocator, buffer, pk.public_key);
        try writer.writeInt(i32, @intFromEnum(pk.algorithm), .little);
        try writeString(allocator, buffer, pk.rp_id);
        try writeOptionalString(allocator, buffer, pk.rp_name);
        try writeString(allocator, buffer, pk.user_handle);
        try writeOptionalString(allocator, buffer, pk.user_name);
        try writer.writeInt(u32, pk.counter, .little);
    }
}

fn serializeCardData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), c: item.CardData) !void {
    const writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, c.cardholder_name);
    try writeOptionalString(allocator, buffer, c.number);
    try writer.writeByte(if (c.brand) |b| @intFromEnum(b) else 0);
    try writer.writeByte(c.exp_month orelse 0);
    try writer.writeInt(u16, c.exp_year orelse 0, .little);
    try writeOptionalString(allocator, buffer, c.cvv);
    try writeOptionalString(allocator, buffer, c.pin);
}

fn serializeIdentityData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), i: item.IdentityData) !void {
    const writer = buffer.writer(allocator);

    try writeOptionalString(allocator, buffer, i.title);
    try writeOptionalString(allocator, buffer, i.first_name);
    try writeOptionalString(allocator, buffer, i.middle_name);
    try writeOptionalString(allocator, buffer, i.last_name);
    try writeOptionalString(allocator, buffer, i.email);
    try writeOptionalString(allocator, buffer, i.phone);

    if (i.address) |a| {
        try writer.writeByte(1);
        try writeOptionalString(allocator, buffer, a.street1);
        try writeOptionalString(allocator, buffer, a.street2);
        try writeOptionalString(allocator, buffer, a.city);
        try writeOptionalString(allocator, buffer, a.state);
        try writeOptionalString(allocator, buffer, a.postal_code);
        try writeOptionalString(allocator, buffer, a.country);
    } else {
        try writer.writeByte(0);
    }

    try writeOptionalString(allocator, buffer, i.ssn);
    try writeOptionalString(allocator, buffer, i.passport);
    try writeOptionalString(allocator, buffer, i.license_number);
    try writeOptionalString(allocator, buffer, i.company);
    try writeOptionalString(allocator, buffer, i.job_title);
}

fn serializeSshKeyData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: item.SshKeyData) !void {
    const writer = buffer.writer(allocator);

    try writeString(allocator, buffer, s.private_key);
    try writeString(allocator, buffer, s.public_key);
    try writeString(allocator, buffer, s.fingerprint);
    try writer.writeByte(@intFromEnum(s.key_type));
    try writeOptionalString(allocator, buffer, s.passphrase);
}

fn serializeApiCredentialData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), a: item.ApiCredentialData) !void {
    try writeOptionalString(allocator, buffer, a.api_key);
    try writeOptionalString(allocator, buffer, a.api_secret);
    try writeOptionalString(allocator, buffer, a.endpoint);
    try writeOptionalString(allocator, buffer, a.documentation_url);
}

fn serializeDatabaseData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), d: item.DatabaseData) !void {
    const writer = buffer.writer(allocator);

    try writer.writeByte(@intFromEnum(d.db_type));
    try writeOptionalString(allocator, buffer, d.host);
    try writer.writeInt(u16, d.port orelse 0, .little);
    try writeOptionalString(allocator, buffer, d.database);
    try writeOptionalString(allocator, buffer, d.username);
    try writeOptionalString(allocator, buffer, d.password);
    try writeOptionalString(allocator, buffer, d.connection_string);
    try writeOptionalString(allocator, buffer, d.sid);
}

fn serializeWifiData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), w: item.WifiData) !void {
    const writer = buffer.writer(allocator);

    try writeString(allocator, buffer, w.ssid);
    try writeOptionalString(allocator, buffer, w.password);
    try writer.writeByte(@intFromEnum(w.security));
    try writer.writeByte(if (w.hidden) 1 else 0);
}

fn serializeLicenseData(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), l: item.LicenseData) !void {
    try writeOptionalString(allocator, buffer, l.license_key);
    try writeOptionalString(allocator, buffer, l.product_name);
    try writeOptionalString(allocator, buffer, l.version);
    try writeOptionalString(allocator, buffer, l.publisher);
    try writeOptionalString(allocator, buffer, l.email);
    try writeOptionalI64(allocator, buffer, l.purchase_date);
    try writeOptionalI64(allocator, buffer, l.expiration_date);
}

fn writeString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: []const u8) !void {
    const writer = buffer.writer(allocator);
    try writer.writeInt(u32, @intCast(s.len), .little);
    try buffer.appendSlice(allocator, s);
}

fn writeOptionalString(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), s: ?[]const u8) !void {
    const writer = buffer.writer(allocator);
    if (s) |str| {
        try writer.writeByte(1);
        try writeString(allocator, buffer, str);
    } else {
        try writer.writeByte(0);
    }
}

fn writeOptionalI64(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), v: ?i64) !void {
    const writer = buffer.writer(allocator);
    if (v) |val| {
        try writer.writeByte(1);
        try writer.writeInt(i64, val, .little);
    } else {
        try writer.writeByte(0);
    }
}

test "serialize empty items" {
    const allocator = std.testing.allocator;
    var items: [0]item.Item = .{};

    const serialized = try serializeItems(allocator, &items);
    defer allocator.free(serialized);

    try std.testing.expectEqual(@as(usize, 4), serialized.len);
}
