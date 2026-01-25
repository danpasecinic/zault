const std = @import("std");
const config = @import("../../core/config.zig");
const generator = @import("../../services/generator.zig");
const clipboard = @import("../../services/clipboard.zig");
const memory = @import("../../memory/secure_allocator.zig");

pub fn run(allocator: std.mem.Allocator, args: []const []const u8, cfg: config.Config) !void {
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
    defer {
        memory.secureZero(result);
        allocator.free(result);
    }

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
