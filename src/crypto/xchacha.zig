const std = @import("std");
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = XChaCha20Poly1305.key_length;
pub const nonce_length = XChaCha20Poly1305.nonce_length;
pub const tag_length = XChaCha20Poly1305.tag_length;

pub const EncryptError = error{
    OutputTooSmall,
};

pub const DecryptError = error{
    AuthenticationFailed,
    OutputTooSmall,
};

pub fn encrypt(
    ciphertext: []u8,
    tag: *[tag_length]u8,
    plaintext: []const u8,
    key: *const [key_length]u8,
    nonce: *const [nonce_length]u8,
) EncryptError!void {
    if (ciphertext.len < plaintext.len) {
        return EncryptError.OutputTooSmall;
    }

    XChaCha20Poly1305.encrypt(
        ciphertext[0..plaintext.len],
        tag,
        plaintext,
        "",
        nonce.*,
        key.*,
    );
}

pub fn decrypt(
    plaintext: []u8,
    ciphertext: []const u8,
    tag: *const [tag_length]u8,
    key: *const [key_length]u8,
    nonce: *const [nonce_length]u8,
) DecryptError!void {
    if (plaintext.len < ciphertext.len) {
        return DecryptError.OutputTooSmall;
    }

    XChaCha20Poly1305.decrypt(
        plaintext[0..ciphertext.len],
        ciphertext,
        tag.*,
        "",
        nonce.*,
        key.*,
    ) catch return DecryptError.AuthenticationFailed;
}

pub fn generateNonce() [nonce_length]u8 {
    var nonce: [nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    return nonce;
}

pub fn encryptedLength(plaintext_len: usize) usize {
    return plaintext_len + tag_length;
}

test "encrypt and decrypt roundtrip" {
    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    const nonce = generateNonce();
    const plaintext = "Hello, World!";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;

    try encrypt(&ciphertext, &tag, plaintext, &key, &nonce);

    var decrypted: [plaintext.len]u8 = undefined;
    try decrypt(&decrypted, &ciphertext, &tag, &key, &nonce);

    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "decrypt fails with wrong key" {
    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    const nonce = generateNonce();
    const plaintext = "Secret data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;

    try encrypt(&ciphertext, &tag, plaintext, &key, &nonce);

    var wrong_key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&decrypted, &ciphertext, &tag, &wrong_key, &nonce);
    try std.testing.expectError(DecryptError.AuthenticationFailed, result);
}

test "decrypt fails with tampered ciphertext" {
    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    const nonce = generateNonce();
    const plaintext = "Secret data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [tag_length]u8 = undefined;

    try encrypt(&ciphertext, &tag, plaintext, &key, &nonce);

    ciphertext[0] ^= 0xFF;

    var decrypted: [plaintext.len]u8 = undefined;
    const result = decrypt(&decrypted, &ciphertext, &tag, &key, &nonce);
    try std.testing.expectError(DecryptError.AuthenticationFailed, result);
}
