const std = @import("std");

pub const ConfigError = error{
    NoHomeDirectory,
    ParseError,
    IoError,
};

pub const Config = struct {
    clipboard_timeout: u32 = 45,
    clipboard_enabled: bool = true,

    password_length: u32 = 20,
    password_uppercase: bool = true,
    password_lowercase: bool = true,
    password_digits: bool = true,
    password_symbols: bool = true,
    password_exclude_ambiguous: bool = true,

    passphrase_words: u32 = 4,
    passphrase_separator: u8 = '-',

    auto_lock_minutes: u32 = 30,

    const Self = @This();

    pub fn load(allocator: std.mem.Allocator) !Self {
        const config_path = try getConfigPath(allocator);
        defer allocator.free(config_path);

        const file = std.fs.cwd().openFile(config_path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                return Self{};
            }
            return ConfigError.IoError;
        };
        defer file.close();

        const file_size = file.getEndPos() catch return ConfigError.IoError;
        if (file_size > 64 * 1024) {
            return ConfigError.IoError;
        }

        const content = allocator.alloc(u8, file_size) catch return ConfigError.IoError;
        defer allocator.free(content);

        const bytes_read = file.readAll(content) catch return ConfigError.IoError;
        if (bytes_read != file_size) {
            return ConfigError.IoError;
        }

        return Self.parse(content);
    }

    pub fn getConfigPath(allocator: std.mem.Allocator) ![]const u8 {
        const home = std.posix.getenv("HOME") orelse return ConfigError.NoHomeDirectory;
        const config_home = std.posix.getenv("XDG_CONFIG_HOME");

        if (config_home) |config| {
            return std.fmt.allocPrint(allocator, "{s}/zault/config.toml", .{config});
        } else {
            return std.fmt.allocPrint(allocator, "{s}/.config/zault/config.toml", .{home});
        }
    }

    pub fn getConfigDir(allocator: std.mem.Allocator) ![]const u8 {
        const home = std.posix.getenv("HOME") orelse return ConfigError.NoHomeDirectory;
        const config_home = std.posix.getenv("XDG_CONFIG_HOME");

        if (config_home) |config| {
            return std.fmt.allocPrint(allocator, "{s}/zault", .{config});
        } else {
            return std.fmt.allocPrint(allocator, "{s}/.config/zault", .{home});
        }
    }

    fn parse(content: []const u8) Self {
        var config = Self{};
        var current_section: Section = .none;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");

            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            if (trimmed[0] == '[') {
                current_section = parseSection(trimmed);
                continue;
            }

            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                applyValue(&config, current_section, key, value);
            }
        }

        return config;
    }

    const Section = enum {
        none,
        clipboard,
        generator,
        passphrase,
        security,
    };

    fn parseSection(line: []const u8) Section {
        if (line.len < 2) return .none;

        const end = std.mem.indexOf(u8, line, "]") orelse return .none;
        if (end <= 1) return .none;

        const section_name = line[1..end];

        if (std.mem.eql(u8, section_name, "clipboard")) return .clipboard;
        if (std.mem.eql(u8, section_name, "generator")) return .generator;
        if (std.mem.eql(u8, section_name, "passphrase")) return .passphrase;
        if (std.mem.eql(u8, section_name, "security")) return .security;

        return .none;
    }

    fn applyValue(config: *Self, section: Section, key: []const u8, value: []const u8) void {
        switch (section) {
            .clipboard => applyClipboardValue(config, key, value),
            .generator => applyGeneratorValue(config, key, value),
            .passphrase => applyPassphraseValue(config, key, value),
            .security => applySecurityValue(config, key, value),
            .none => {},
        }
    }

    fn applyClipboardValue(config: *Self, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "timeout")) {
            config.clipboard_timeout = parseU32(value) orelse config.clipboard_timeout;
        } else if (std.mem.eql(u8, key, "enabled")) {
            config.clipboard_enabled = parseBool(value) orelse config.clipboard_enabled;
        }
    }

    fn applyGeneratorValue(config: *Self, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "length")) {
            config.password_length = parseU32(value) orelse config.password_length;
        } else if (std.mem.eql(u8, key, "uppercase")) {
            config.password_uppercase = parseBool(value) orelse config.password_uppercase;
        } else if (std.mem.eql(u8, key, "lowercase")) {
            config.password_lowercase = parseBool(value) orelse config.password_lowercase;
        } else if (std.mem.eql(u8, key, "digits")) {
            config.password_digits = parseBool(value) orelse config.password_digits;
        } else if (std.mem.eql(u8, key, "symbols")) {
            config.password_symbols = parseBool(value) orelse config.password_symbols;
        } else if (std.mem.eql(u8, key, "exclude_ambiguous")) {
            config.password_exclude_ambiguous = parseBool(value) orelse config.password_exclude_ambiguous;
        }
    }

    fn applyPassphraseValue(config: *Self, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "words")) {
            config.passphrase_words = parseU32(value) orelse config.passphrase_words;
        } else if (std.mem.eql(u8, key, "separator")) {
            const parsed = parseString(value);
            if (parsed.len > 0) {
                config.passphrase_separator = parsed[0];
            }
        }
    }

    fn applySecurityValue(config: *Self, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "auto_lock_minutes")) {
            if (parseU32(value)) |minutes| {
                // Cap at 24 hours (1440 minutes) to prevent unreasonable values
                config.auto_lock_minutes = if (minutes > 1440) 1440 else minutes;
            }
        }
    }

    fn parseU32(value: []const u8) ?u32 {
        return std.fmt.parseInt(u32, value, 10) catch null;
    }

    fn parseBool(value: []const u8) ?bool {
        if (std.mem.eql(u8, value, "true")) return true;
        if (std.mem.eql(u8, value, "false")) return false;
        return null;
    }

    fn parseString(value: []const u8) []const u8 {
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                return value[1 .. value.len - 1];
            }
        }
        return value;
    }
};

test "config default values" {
    const config = Config{};

    try std.testing.expectEqual(@as(u32, 45), config.clipboard_timeout);
    try std.testing.expectEqual(true, config.clipboard_enabled);
    try std.testing.expectEqual(@as(u32, 20), config.password_length);
    try std.testing.expectEqual(true, config.password_uppercase);
    try std.testing.expectEqual(@as(u32, 4), config.passphrase_words);
    try std.testing.expectEqual(@as(u8, '-'), config.passphrase_separator);
    try std.testing.expectEqual(@as(u32, 30), config.auto_lock_minutes);
}

test "config parse empty" {
    const config = Config.parse("");

    try std.testing.expectEqual(@as(u32, 45), config.clipboard_timeout);
    try std.testing.expectEqual(@as(u32, 20), config.password_length);
}

test "config parse comments" {
    const content =
        \\# This is a comment
        \\[clipboard]
        \\# timeout = 30
        \\timeout = 60
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 60), config.clipboard_timeout);
}

test "config parse all sections" {
    const content =
        \\[clipboard]
        \\timeout = 30
        \\enabled = false
        \\
        \\[generator]
        \\length = 32
        \\uppercase = false
        \\lowercase = true
        \\digits = true
        \\symbols = false
        \\exclude_ambiguous = false
        \\
        \\[passphrase]
        \\words = 6
        \\separator = "_"
        \\
        \\[security]
        \\auto_lock_minutes = 15
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 30), config.clipboard_timeout);
    try std.testing.expectEqual(false, config.clipboard_enabled);
    try std.testing.expectEqual(@as(u32, 32), config.password_length);
    try std.testing.expectEqual(false, config.password_uppercase);
    try std.testing.expectEqual(true, config.password_lowercase);
    try std.testing.expectEqual(true, config.password_digits);
    try std.testing.expectEqual(false, config.password_symbols);
    try std.testing.expectEqual(false, config.password_exclude_ambiguous);
    try std.testing.expectEqual(@as(u32, 6), config.passphrase_words);
    try std.testing.expectEqual(@as(u8, '_'), config.passphrase_separator);
    try std.testing.expectEqual(@as(u32, 15), config.auto_lock_minutes);
}

test "config parse invalid values fallback to default" {
    const content =
        \\[clipboard]
        \\timeout = invalid
        \\enabled = maybe
        \\
        \\[generator]
        \\length = -5
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 45), config.clipboard_timeout);
    try std.testing.expectEqual(true, config.clipboard_enabled);
    try std.testing.expectEqual(@as(u32, 20), config.password_length);
}

test "config parse unknown section" {
    const content =
        \\[unknown]
        \\foo = bar
        \\
        \\[clipboard]
        \\timeout = 25
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 25), config.clipboard_timeout);
}

test "config parse whitespace handling" {
    const content = "[clipboard]\n  timeout   =   50\n\tenabled\t=\ttrue";

    const cfg = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 50), cfg.clipboard_timeout);
    try std.testing.expectEqual(true, cfg.clipboard_enabled);
}

test "config path generation" {
    const allocator = std.testing.allocator;

    const config_path = Config.getConfigPath(allocator) catch return;
    defer allocator.free(config_path);

    try std.testing.expect(std.mem.endsWith(u8, config_path, "zault/config.toml"));
}

test "config auto_lock_minutes capped at 24 hours" {
    const content =
        \\[security]
        \\auto_lock_minutes = 9999
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 1440), config.auto_lock_minutes);
}

test "config auto_lock_minutes accepts valid values" {
    const content =
        \\[security]
        \\auto_lock_minutes = 60
    ;

    const config = Config.parse(content);

    try std.testing.expectEqual(@as(u32, 60), config.auto_lock_minutes);
}
