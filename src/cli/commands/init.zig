const std = @import("std");
const core = @import("../../core/vault.zig");
const config = @import("../../core/config.zig");
const terminal = @import("../terminal.zig");
const memory = @import("../../memory/secure_allocator.zig");

pub fn run(allocator: std.mem.Allocator, _: []const []const u8, _: config.Config) !void {
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
