const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const cli = @import("cli/root.zig");
const terminal = @import("cli/terminal.zig");
const core = @import("core/vault.zig");
const config = @import("core/config.zig");
const entry = @import("core/entry.zig");
const memory = @import("memory/secure_allocator.zig");
const argon2 = @import("crypto/argon2.zig");
const xchacha = @import("crypto/xchacha.zig");
const totp = @import("services/totp.zig");
const generator = @import("services/generator.zig");
const clipboard = @import("services/clipboard.zig");

pub const std_options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cfg = config.Config.load(allocator) catch config.Config{};

    if (try core.checkLegacyVaultExists(allocator)) {
        std.debug.print("Note: Found vault at legacy location (~/.config/zault/vault.zault).\n", .{});
        std.debug.print("Consider migrating to ~/.local/share/zault/vault.zault\n\n", .{});
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try showHelp();
        return;
    }

    const command = args[1];
    try runCommand(allocator, cfg, command, args[2..]);
}

fn runCommand(allocator: std.mem.Allocator, cfg: config.Config, command: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, command, "init")) {
        try cmdInit(allocator);
    } else if (std.mem.eql(u8, command, "add")) {
        try cmdAdd(allocator, args);
    } else if (std.mem.eql(u8, command, "get")) {
        try cmdGet(allocator, args, cfg);
    } else if (std.mem.eql(u8, command, "list")) {
        try cmdList(allocator);
    } else if (std.mem.eql(u8, command, "delete")) {
        try cmdDelete();
    } else if (std.mem.eql(u8, command, "generate")) {
        try cmdGenerate(allocator, args, cfg);
    } else if (std.mem.eql(u8, command, "totp")) {
        try cmdTotp();
    } else if (std.mem.eql(u8, command, "passkey")) {
        try cmdPasskey();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try showHelp();
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        try showVersion();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        std.debug.print("Run 'zault help' for usage information.\n", .{});
    }
}

fn cmdInit(allocator: std.mem.Allocator) !void {
    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    if (std.fs.cwd().access(vault_path, .{})) |_| {
        std.debug.print("Vault already exists at {s}\n", .{vault_path});
        std.debug.print("Use 'zault delete-vault' to remove it first.\n", .{});
        return;
    } else |_| {}

    std.debug.print("Creating new vault at {s}\n", .{vault_path});

    const password = terminal.readPassword(allocator, "Enter master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    if (password.len < 8) {
        std.debug.print("Error: Password must be at least 8 characters\n", .{});
        return;
    }

    const confirm_pw = terminal.readPassword(allocator, "Confirm master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(confirm_pw);
        allocator.free(confirm_pw);
    }

    if (!std.mem.eql(u8, password, confirm_pw)) {
        std.debug.print("Error: Passwords do not match\n", .{});
        return;
    }

    var vault = core.Vault.create(allocator, vault_path, password) catch {
        std.debug.print("Error: Could not create vault\n", .{});
        return;
    };
    defer vault.deinit();

    vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Vault created successfully.\n", .{});
}

fn cmdAdd(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
            },
        }
        return;
    };
    defer vault.deinit();

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
            },
        }
        return;
    };

    const entry_name = if (args.len > 0)
        args[0]
    else blk: {
        const name = terminal.readLine(allocator, "Entry name: ") catch {
            std.debug.print("Error: Could not read entry name\n", .{});
            return;
        };
        if (name.len == 0) {
            allocator.free(name);
            std.debug.print("Error: Entry name cannot be empty\n", .{});
            return;
        }
        break :blk name;
    };
    const should_free_name = args.len == 0;
    defer if (should_free_name) allocator.free(entry_name);

    const username = terminal.readLine(allocator, "Username (optional): ") catch {
        std.debug.print("Error: Could not read username\n", .{});
        return;
    };
    defer allocator.free(username);
    const username_opt: ?[]const u8 = if (username.len > 0) username else null;

    const entry_password = terminal.readPassword(allocator, "Password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(entry_password);
        allocator.free(entry_password);
    }

    if (entry_password.len == 0) {
        std.debug.print("Error: Password cannot be empty\n", .{});
        return;
    }

    const url = terminal.readLine(allocator, "URL (optional): ") catch {
        std.debug.print("Error: Could not read URL\n", .{});
        return;
    };
    defer allocator.free(url);
    const url_opt: ?[]const u8 = if (url.len > 0) url else null;

    const new_entry = entry.createPasswordEntry(
        allocator,
        entry_name,
        username_opt,
        entry_password,
        url_opt,
    ) catch {
        std.debug.print("Error: Could not create entry\n", .{});
        return;
    };

    vault.addEntry(new_entry) catch |err| {
        var mutable_entry = new_entry;
        mutable_entry.deinit(allocator);
        switch (err) {
            core.VaultError.EntryAlreadyExists => {
                std.debug.print("Error: Entry '{s}' already exists\n", .{entry_name});
            },
            else => {
                std.debug.print("Error: Could not add entry\n", .{});
            },
        }
        return;
    };

    vault.save() catch {
        std.debug.print("Error: Could not save vault\n", .{});
        return;
    };

    std.debug.print("Entry '{s}' added successfully.\n", .{entry_name});
}

fn cmdGet(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    if (args.len == 0) {
        std.debug.print("Usage: zault get <name>\n", .{});
        return;
    }

    const entry_name = args[0];

    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
            },
        }
        return;
    };
    defer vault.deinit();

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
            },
        }
        return;
    };

    const found_entry = vault.getEntry(entry_name);
    if (found_entry == null) {
        std.debug.print("Error: Entry '{s}' not found\n", .{entry_name});
        return;
    }

    const e = found_entry.?;
    switch (e.data) {
        .password => |pwd| {
            if (!cfg.clipboard_enabled) {
                std.debug.print("Clipboard disabled in config. Password for '{s}':\n{s}\n", .{ entry_name, pwd.password });
                return;
            }

            clipboard.copyWithTimeout(allocator, pwd.password, cfg.clipboard_timeout) catch {
                std.debug.print("Error: Could not copy to clipboard. Password:\n{s}\n", .{pwd.password});
                return;
            };

            std.debug.print("Password for '{s}' copied to clipboard.", .{entry_name});
            if (cfg.clipboard_timeout > 0) {
                std.debug.print(" Clearing in {d}s.", .{cfg.clipboard_timeout});
            }
            std.debug.print("\n", .{});

            if (pwd.username) |u| {
                std.debug.print("Username: {s}\n", .{u});
            }
            if (pwd.url) |url| {
                std.debug.print("URL: {s}\n", .{url});
            }
        },
        .totp => {
            std.debug.print("Entry '{s}' is a TOTP entry. Use 'zault totp {s}' instead.\n", .{ entry_name, entry_name });
        },
        .passkey => {
            std.debug.print("Entry '{s}' is a passkey entry.\n", .{entry_name});
        },
    }
}

fn cmdList(allocator: std.mem.Allocator) !void {
    const vault_path = core.getDefaultVaultDataPath(allocator) catch {
        std.debug.print("Error: Could not determine vault path\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    var vault = core.Vault.open(allocator, vault_path) catch |err| {
        switch (err) {
            core.VaultError.VaultNotFound => {
                std.debug.print("Error: No vault found. Run 'zault init' first.\n", .{});
            },
            else => {
                std.debug.print("Error: Could not open vault\n", .{});
            },
        }
        return;
    };
    defer vault.deinit();

    const password = terminal.readPassword(allocator, "Master password: ") catch {
        std.debug.print("Error: Could not read password\n", .{});
        return;
    };
    defer {
        memory.secureZero(password);
        allocator.free(password);
    }

    vault.unlock(password) catch |err| {
        switch (err) {
            core.VaultError.InvalidMasterPassword => {
                std.debug.print("Error: Invalid master password\n", .{});
            },
            else => {
                std.debug.print("Error: Could not unlock vault\n", .{});
            },
        }
        return;
    };

    if (vault.entries.items.len == 0) {
        std.debug.print("Vault is empty. Use 'zault add <name>' to add entries.\n", .{});
        return;
    }

    std.debug.print("Entries ({d}):\n", .{vault.entries.items.len});
    std.debug.print("{s:<30} {s:<12} {s}\n", .{ "NAME", "TYPE", "USERNAME/ISSUER" });
    std.debug.print("{s}\n", .{"-" ** 60});

    for (vault.entries.items) |e| {
        const type_str = switch (e.entry_type) {
            .password => "password",
            .totp => "totp",
            .passkey => "passkey",
        };

        const extra = switch (e.data) {
            .password => |p| p.username orelse "",
            .totp => |t| t.issuer orelse "",
            .passkey => |pk| pk.user_name orelse "",
        };

        std.debug.print("{s:<30} {s:<12} {s}\n", .{ e.name, type_str, extra });
    }
}

fn cmdDelete() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdGenerate(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
    var use_passphrase = false;
    var copy_to_clipboard = false;
    var length: u32 = cfg.password_length;
    var words: u32 = cfg.passphrase_words;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--passphrase") or std.mem.eql(u8, arg, "-p")) {
            use_passphrase = true;
        } else if (std.mem.eql(u8, arg, "--copy") or std.mem.eql(u8, arg, "-c")) {
            copy_to_clipboard = true;
        } else if (std.mem.eql(u8, arg, "--length") or std.mem.eql(u8, arg, "-l")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --length requires a value\n", .{});
                return;
            }
            length = std.fmt.parseInt(u32, args[i], 10) catch {
                std.debug.print("Error: Invalid length value\n", .{});
                return;
            };
        } else if (std.mem.eql(u8, arg, "--words") or std.mem.eql(u8, arg, "-w")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --words requires a value\n", .{});
                return;
            }
            words = std.fmt.parseInt(u32, args[i], 10) catch {
                std.debug.print("Error: Invalid words value\n", .{});
                return;
            };
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print(
                \\Usage: zault generate [options]
                \\
                \\Options:
                \\  -l, --length <n>  Password length (default: {d})
                \\  -p, --passphrase  Generate passphrase instead
                \\  -w, --words <n>   Number of words for passphrase (default: {d})
                \\  -c, --copy        Copy to clipboard
                \\  -h, --help        Show this help
                \\
            , .{ cfg.password_length, cfg.passphrase_words });
            return;
        }
    }

    const result = if (use_passphrase)
        generator.generatePassphrase(allocator, words, cfg.passphrase_separator) catch {
            std.debug.print("Error: Could not generate passphrase\n", .{});
            return;
        }
    else
        generator.generate(allocator, .{
            .length = length,
            .uppercase = cfg.password_uppercase,
            .lowercase = cfg.password_lowercase,
            .digits = cfg.password_digits,
            .symbols = cfg.password_symbols,
            .exclude_ambiguous = cfg.password_exclude_ambiguous,
        }) catch {
            std.debug.print("Error: Could not generate password\n", .{});
            return;
        };
    defer allocator.free(result);

    std.debug.print("{s}\n", .{result});

    const entropy = generator.calculateEntropy(result);
    std.debug.print("Entropy: {d:.1} bits\n", .{entropy});

    if (copy_to_clipboard) {
        if (!cfg.clipboard_enabled) {
            std.debug.print("Clipboard disabled in config.\n", .{});
            return;
        }
        clipboard.copyWithTimeout(allocator, result, cfg.clipboard_timeout) catch {
            std.debug.print("Error: Could not copy to clipboard\n", .{});
            return;
        };
        std.debug.print("Copied to clipboard.", .{});
        if (cfg.clipboard_timeout > 0) {
            std.debug.print(" Clearing in {d}s.", .{cfg.clipboard_timeout});
        }
        std.debug.print("\n", .{});
    }
}

fn cmdTotp() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn cmdPasskey() !void {
    std.debug.print("Not yet implemented\n", .{});
}

fn showHelp() !void {
    const help =
        \\zault - A secure credential manager
        \\
        \\USAGE:
        \\    zault [command] [options]
        \\
        \\COMMANDS:
        \\    init              Create a new vault
        \\    add <name>        Add a new credential
        \\    get <name>        Retrieve a credential (copies to clipboard)
        \\    list              List all entries
        \\    delete <name>     Remove an entry
        \\    generate          Generate a secure password
        \\    totp <subcommand> TOTP operations (add, list, get)
        \\    passkey <subcmd>  Passkey operations (list, delete)
        \\    help              Show this help message
        \\    version           Show version information
        \\
        \\OPTIONS:
        \\    -h, --help        Show help for a command
        \\    -v, --version     Show version
        \\
        \\EXAMPLES:
        \\    zault init
        \\    zault add github.com -u myuser
        \\    zault get github.com
        \\    zault totp add github.com
        \\    zault totp github.com
        \\
        \\For more information, visit: https://github.com/danpasecinic/zault
        \\
    ;
    std.debug.print("{s}", .{help});
}

fn showVersion() !void {
    std.debug.print("zault version {s}\n", .{build_options.version});
}

test "basic command parsing" {
    try showVersion();
}

test {
    @import("std").testing.refAllDecls(@This());
    _ = cli;
    _ = core;
    _ = config;
    _ = entry;
    _ = memory;
    _ = argon2;
    _ = xchacha;
    _ = totp;
    _ = generator;
    _ = clipboard;
}
