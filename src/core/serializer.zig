const std = @import("std");
const item = @import("item.zig");
const Uuid = @import("uuid.zig").Uuid;

pub const SerializeError = error{
    BufferTooSmall,
    OutOfMemory,
    InvalidData,
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

pub fn deserializeItems(allocator: std.mem.Allocator, data: []const u8) ![]item.Item {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();

    const count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    var items: std.ArrayList(item.Item) = .empty;
    errdefer {
        for (items.items) |*i| i.deinit(allocator);
        items.deinit(allocator);
    }

    for (0..count) |_| {
        const i = try deserializeItem(allocator, reader);
        try items.append(allocator, i);
    }

    return items.toOwnedSlice(allocator);
}

fn deserializeItem(allocator: std.mem.Allocator, reader: anytype) !item.Item {
    var uuid_bytes: [16]u8 = undefined;
    _ = reader.readAll(&uuid_bytes) catch return DeserializeError.UnexpectedEndOfData;
    const id = Uuid.fromBytes(uuid_bytes);

    const name = try readString(allocator, reader);
    errdefer allocator.free(name);

    const notes = try readOptionalString(allocator, reader);
    errdefer if (notes) |n| allocator.free(n);

    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const item_type = std.meta.intToEnum(item.ItemType, type_byte) catch return DeserializeError.InvalidItemType;

    const favorite_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const favorite = favorite_byte == 1;

    const created_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    const modified_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    const last_accessed_at = try readOptionalI64(reader);
    const access_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    const deleted_at = try readOptionalI64(reader);

    const fields_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var fields = try allocator.alloc(item.CustomField, fields_count);
    var fields_initialized: usize = 0;
    errdefer {
        for (0..fields_initialized) |j| {
            var f = fields[j];
            f.deinit(allocator);
        }
        allocator.free(fields);
    }

    for (0..fields_count) |i| {
        fields[i] = try deserializeCustomField(allocator, reader);
        fields_initialized = i + 1;
    }

    const history_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var history = try allocator.alloc(item.PasswordHistoryEntry, history_count);
    var history_initialized: usize = 0;
    errdefer {
        for (0..history_initialized) |j| {
            var h = history[j];
            h.deinit(allocator);
        }
        allocator.free(history);
    }

    for (0..history_count) |i| {
        const pw = try readString(allocator, reader);
        errdefer {
            @memset(@constCast(pw), 0);
            allocator.free(pw);
        }
        const changed_at = reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
        history[i] = .{ .password = pw, .changed_at = changed_at };
        history_initialized = i + 1;
    }

    const data = try deserializeItemData(allocator, reader, item_type);

    return item.Item{
        .id = id,
        .name = name,
        .notes = notes,
        .item_type = item_type,
        .data = data,
        .favorite = favorite,
        .fields = fields,
        .password_history = history,
        .created_at = created_at,
        .modified_at = modified_at,
        .last_accessed_at = last_accessed_at,
        .access_count = access_count,
        .deleted_at = deleted_at,
    };
}

fn deserializeCustomField(allocator: std.mem.Allocator, reader: anytype) !item.CustomField {
    const name = try readString(allocator, reader);
    errdefer allocator.free(name);

    const value = try readOptionalString(allocator, reader);
    errdefer if (value) |v| allocator.free(v);

    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const field_type = std.meta.intToEnum(item.FieldType, type_byte) catch return DeserializeError.InvalidData;

    return .{
        .name = name,
        .value = value,
        .field_type = field_type,
    };
}

fn deserializeItemData(allocator: std.mem.Allocator, reader: anytype, item_type: item.ItemType) !item.ItemData {
    return switch (item_type) {
        .login => .{ .login = try deserializeLoginData(allocator, reader) },
        .secure_note => .{ .secure_note = .{} },
        .card => .{ .card = try deserializeCardData(allocator, reader) },
        .identity => .{ .identity = try deserializeIdentityData(allocator, reader) },
        .ssh_key => .{ .ssh_key = try deserializeSshKeyData(allocator, reader) },
        .api_credential => .{ .api_credential = try deserializeApiCredentialData(allocator, reader) },
        .database => .{ .database = try deserializeDatabaseData(allocator, reader) },
        .wifi => .{ .wifi = try deserializeWifiData(allocator, reader) },
        .license => .{ .license = try deserializeLicenseData(allocator, reader) },
    };
}

fn deserializeLoginData(allocator: std.mem.Allocator, reader: anytype) !item.LoginData {
    const username = try readOptionalString(allocator, reader);
    errdefer if (username) |u| allocator.free(u);

    const password = try readOptionalString(allocator, reader);
    errdefer if (password) |p| {
        @memset(@constCast(p), 0);
        allocator.free(p);
    };

    const uri_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var uris = try allocator.alloc(item.Uri, uri_count);
    var uris_initialized: usize = 0;
    errdefer {
        for (0..uris_initialized) |j| {
            allocator.free(uris[j].uri);
        }
        allocator.free(uris);
    }

    for (0..uri_count) |i| {
        const uri_str = try readString(allocator, reader);
        errdefer allocator.free(uri_str);
        const match_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const match_type = std.meta.intToEnum(item.UriMatchType, match_byte) catch return DeserializeError.InvalidData;
        uris[i] = .{ .uri = uri_str, .match_type = match_type };
        uris_initialized = i + 1;
    }

    const has_totp = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    var totp: ?item.TotpData = null;
    if (has_totp == 1) {
        const secret = try readString(allocator, reader);
        errdefer {
            @memset(@constCast(secret), 0);
            allocator.free(secret);
        }
        const algo_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const algorithm = std.meta.intToEnum(item.TotpAlgorithm, algo_byte) catch return DeserializeError.InvalidData;
        const digits = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
        const period = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
        totp = .{
            .secret = secret,
            .algorithm = algorithm,
            .digits = digits,
            .period = period,
        };
    }
    errdefer if (totp) |*t| {
        var td = t.*;
        td.deinit(allocator);
    };

    const pk_count = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    var passkeys = try allocator.alloc(item.PasskeyData, pk_count);
    var passkeys_initialized: usize = 0;
    errdefer {
        for (0..passkeys_initialized) |j| {
            var pk = passkeys[j];
            pk.deinit(allocator);
        }
        allocator.free(passkeys);
    }

    for (0..pk_count) |i| {
        passkeys[i] = try deserializePasskeyData(allocator, reader);
        passkeys_initialized = i + 1;
    }

    return .{
        .username = username,
        .password = password,
        .uris = uris,
        .totp = totp,
        .passkeys = passkeys,
    };
}

fn deserializePasskeyData(allocator: std.mem.Allocator, reader: anytype) !item.PasskeyData {
    const credential_id = try readString(allocator, reader);
    errdefer allocator.free(credential_id);

    const private_key = try readString(allocator, reader);
    errdefer {
        @memset(@constCast(private_key), 0);
        allocator.free(private_key);
    }

    const public_key = try readString(allocator, reader);
    errdefer allocator.free(public_key);

    const algo_int = reader.readInt(i32, .little) catch return DeserializeError.UnexpectedEndOfData;
    const algorithm = std.meta.intToEnum(item.PasskeyAlgorithm, algo_int) catch return DeserializeError.InvalidData;

    const rp_id = try readString(allocator, reader);
    errdefer allocator.free(rp_id);

    const rp_name = try readOptionalString(allocator, reader);
    errdefer if (rp_name) |n| allocator.free(n);

    const user_handle = try readString(allocator, reader);
    errdefer allocator.free(user_handle);

    const user_name = try readOptionalString(allocator, reader);
    errdefer if (user_name) |n| allocator.free(n);

    const counter = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;

    return .{
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

fn deserializeCardData(allocator: std.mem.Allocator, reader: anytype) !item.CardData {
    const cardholder = try readOptionalString(allocator, reader);
    errdefer if (cardholder) |c| allocator.free(c);

    const number = try readOptionalString(allocator, reader);
    errdefer if (number) |n| {
        @memset(@constCast(n), 0);
        allocator.free(n);
    };

    const brand_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const brand: ?item.CardBrand = if (brand_byte == 0) null else std.meta.intToEnum(item.CardBrand, brand_byte) catch return DeserializeError.InvalidData;
    const exp_month_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const exp_month: ?u8 = if (exp_month_byte == 0) null else exp_month_byte;
    const exp_year_val = reader.readInt(u16, .little) catch return DeserializeError.UnexpectedEndOfData;
    const exp_year: ?u16 = if (exp_year_val == 0) null else exp_year_val;

    const cvv = try readOptionalString(allocator, reader);
    errdefer if (cvv) |c| {
        @memset(@constCast(c), 0);
        allocator.free(c);
    };

    const pin = try readOptionalString(allocator, reader);
    errdefer if (pin) |p| {
        @memset(@constCast(p), 0);
        allocator.free(p);
    };

    return .{
        .cardholder_name = cardholder,
        .number = number,
        .brand = brand,
        .exp_month = exp_month,
        .exp_year = exp_year,
        .cvv = cvv,
        .pin = pin,
    };
}

fn deserializeIdentityData(allocator: std.mem.Allocator, reader: anytype) !item.IdentityData {
    const title = try readOptionalString(allocator, reader);
    errdefer if (title) |t| allocator.free(t);

    const first_name = try readOptionalString(allocator, reader);
    errdefer if (first_name) |f| allocator.free(f);

    const middle_name = try readOptionalString(allocator, reader);
    errdefer if (middle_name) |m| allocator.free(m);

    const last_name = try readOptionalString(allocator, reader);
    errdefer if (last_name) |l| allocator.free(l);

    const email = try readOptionalString(allocator, reader);
    errdefer if (email) |e| allocator.free(e);

    const phone = try readOptionalString(allocator, reader);
    errdefer if (phone) |p| allocator.free(p);

    const has_address = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    var address: ?item.AddressData = null;
    if (has_address == 1) {
        const street1 = try readOptionalString(allocator, reader);
        errdefer if (street1) |s| allocator.free(s);
        const street2 = try readOptionalString(allocator, reader);
        errdefer if (street2) |s| allocator.free(s);
        const city = try readOptionalString(allocator, reader);
        errdefer if (city) |c| allocator.free(c);
        const state = try readOptionalString(allocator, reader);
        errdefer if (state) |s| allocator.free(s);
        const postal_code = try readOptionalString(allocator, reader);
        errdefer if (postal_code) |p| allocator.free(p);
        const country = try readOptionalString(allocator, reader);
        errdefer if (country) |c| allocator.free(c);
        address = .{
            .street1 = street1,
            .street2 = street2,
            .city = city,
            .state = state,
            .postal_code = postal_code,
            .country = country,
        };
    }
    errdefer if (address) |a| {
        if (a.street1) |s| allocator.free(s);
        if (a.street2) |s| allocator.free(s);
        if (a.city) |c| allocator.free(c);
        if (a.state) |s| allocator.free(s);
        if (a.postal_code) |p| allocator.free(p);
        if (a.country) |c| allocator.free(c);
    };

    const ssn = try readOptionalString(allocator, reader);
    errdefer if (ssn) |s| {
        @memset(@constCast(s), 0);
        allocator.free(s);
    };

    const passport = try readOptionalString(allocator, reader);
    errdefer if (passport) |p| {
        @memset(@constCast(p), 0);
        allocator.free(p);
    };

    const license_number = try readOptionalString(allocator, reader);
    errdefer if (license_number) |l| {
        @memset(@constCast(l), 0);
        allocator.free(l);
    };

    const company = try readOptionalString(allocator, reader);
    errdefer if (company) |c| allocator.free(c);

    const job_title = try readOptionalString(allocator, reader);

    return .{
        .title = title,
        .first_name = first_name,
        .middle_name = middle_name,
        .last_name = last_name,
        .email = email,
        .phone = phone,
        .address = address,
        .ssn = ssn,
        .passport = passport,
        .license_number = license_number,
        .company = company,
        .job_title = job_title,
    };
}

fn deserializeSshKeyData(allocator: std.mem.Allocator, reader: anytype) !item.SshKeyData {
    const private_key = try readString(allocator, reader);
    errdefer {
        @memset(@constCast(private_key), 0);
        allocator.free(private_key);
    }

    const public_key = try readString(allocator, reader);
    errdefer allocator.free(public_key);

    const fingerprint = try readString(allocator, reader);
    errdefer allocator.free(fingerprint);

    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const key_type = std.meta.intToEnum(item.SshKeyType, type_byte) catch return DeserializeError.InvalidData;

    const passphrase = try readOptionalString(allocator, reader);

    return .{
        .private_key = private_key,
        .public_key = public_key,
        .fingerprint = fingerprint,
        .key_type = key_type,
        .passphrase = passphrase,
    };
}

fn deserializeApiCredentialData(allocator: std.mem.Allocator, reader: anytype) !item.ApiCredentialData {
    const api_key = try readOptionalString(allocator, reader);
    errdefer if (api_key) |k| {
        @memset(@constCast(k), 0);
        allocator.free(k);
    };

    const api_secret = try readOptionalString(allocator, reader);
    errdefer if (api_secret) |s| {
        @memset(@constCast(s), 0);
        allocator.free(s);
    };

    const endpoint = try readOptionalString(allocator, reader);
    errdefer if (endpoint) |e| allocator.free(e);

    const documentation_url = try readOptionalString(allocator, reader);

    return .{
        .api_key = api_key,
        .api_secret = api_secret,
        .endpoint = endpoint,
        .documentation_url = documentation_url,
    };
}

fn deserializeDatabaseData(allocator: std.mem.Allocator, reader: anytype) !item.DatabaseData {
    const type_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const db_type = std.meta.intToEnum(item.DatabaseType, type_byte) catch return DeserializeError.InvalidData;

    const host = try readOptionalString(allocator, reader);
    errdefer if (host) |h| allocator.free(h);

    const port_val = reader.readInt(u16, .little) catch return DeserializeError.UnexpectedEndOfData;
    const port: ?u16 = if (port_val == 0) null else port_val;

    const database = try readOptionalString(allocator, reader);
    errdefer if (database) |d| allocator.free(d);

    const username = try readOptionalString(allocator, reader);
    errdefer if (username) |u| allocator.free(u);

    const password = try readOptionalString(allocator, reader);
    errdefer if (password) |p| {
        @memset(@constCast(p), 0);
        allocator.free(p);
    };

    const connection_string = try readOptionalString(allocator, reader);
    errdefer if (connection_string) |c| {
        @memset(@constCast(c), 0);
        allocator.free(c);
    };

    const sid = try readOptionalString(allocator, reader);

    return .{
        .db_type = db_type,
        .host = host,
        .port = port,
        .database = database,
        .username = username,
        .password = password,
        .connection_string = connection_string,
        .sid = sid,
    };
}

fn deserializeWifiData(allocator: std.mem.Allocator, reader: anytype) !item.WifiData {
    const ssid = try readString(allocator, reader);
    errdefer allocator.free(ssid);

    const password = try readOptionalString(allocator, reader);
    errdefer if (password) |p| {
        @memset(@constCast(p), 0);
        allocator.free(p);
    };

    const sec_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    const security = std.meta.intToEnum(item.WifiSecurity, sec_byte) catch return DeserializeError.InvalidData;
    const hidden_byte = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;

    return .{
        .ssid = ssid,
        .password = password,
        .security = security,
        .hidden = hidden_byte == 1,
    };
}

fn deserializeLicenseData(allocator: std.mem.Allocator, reader: anytype) !item.LicenseData {
    const license_key = try readOptionalString(allocator, reader);
    errdefer if (license_key) |k| {
        @memset(@constCast(k), 0);
        allocator.free(k);
    };

    const product_name = try readOptionalString(allocator, reader);
    errdefer if (product_name) |p| allocator.free(p);

    const version = try readOptionalString(allocator, reader);
    errdefer if (version) |v| allocator.free(v);

    const publisher = try readOptionalString(allocator, reader);
    errdefer if (publisher) |p| allocator.free(p);

    const email = try readOptionalString(allocator, reader);
    errdefer if (email) |e| allocator.free(e);

    const purchase_date = try readOptionalI64(reader);
    const expiration_date = try readOptionalI64(reader);

    return .{
        .license_key = license_key,
        .product_name = product_name,
        .version = version,
        .publisher = publisher,
        .email = email,
        .purchase_date = purchase_date,
        .expiration_date = expiration_date,
    };
}

fn readString(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    const len = reader.readInt(u32, .little) catch return DeserializeError.UnexpectedEndOfData;
    if (len > 1024 * 1024) return DeserializeError.InvalidData;

    const str = try allocator.alloc(u8, len);
    errdefer allocator.free(str);

    const bytes_read = reader.readAll(str) catch return DeserializeError.UnexpectedEndOfData;
    if (bytes_read != len) return DeserializeError.UnexpectedEndOfData;

    return str;
}

fn readOptionalString(allocator: std.mem.Allocator, reader: anytype) !?[]u8 {
    const present = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    if (present == 1) {
        return try readString(allocator, reader);
    }
    return null;
}

fn readOptionalI64(reader: anytype) !?i64 {
    const present = reader.readByte() catch return DeserializeError.UnexpectedEndOfData;
    if (present == 1) {
        return reader.readInt(i64, .little) catch return DeserializeError.UnexpectedEndOfData;
    }
    return null;
}

test "serialize and deserialize login item roundtrip" {
    const allocator = std.testing.allocator;

    var login_item = try item.createLoginItem(allocator, "github.com", "testuser", "secretpass", "https://github.com");
    defer login_item.deinit(allocator);

    var items_arr = [_]item.Item{login_item};

    const serialized = try serializeItems(allocator, &items_arr);
    defer allocator.free(serialized);

    const deserialized = try deserializeItems(allocator, serialized);
    defer {
        for (deserialized) |*i| i.deinit(allocator);
        allocator.free(deserialized);
    }

    try std.testing.expectEqual(@as(usize, 1), deserialized.len);
    try std.testing.expectEqualStrings("github.com", deserialized[0].name);
    try std.testing.expectEqual(item.ItemType.login, deserialized[0].item_type);
    try std.testing.expectEqualStrings("testuser", deserialized[0].data.login.username.?);
    try std.testing.expectEqualStrings("secretpass", deserialized[0].data.login.password.?);
}

test "serialize empty items" {
    const allocator = std.testing.allocator;
    var items_arr: [0]item.Item = .{};

    const serialized = try serializeItems(allocator, &items_arr);
    defer allocator.free(serialized);

    try std.testing.expectEqual(@as(usize, 4), serialized.len);

    const deserialized = try deserializeItems(allocator, serialized);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(@as(usize, 0), deserialized.len);
}
