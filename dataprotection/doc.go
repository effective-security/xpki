// Package dataprotection provides authenticated encryption of small payloads
// behind the Provider interface, plus helpers to protect and unprotect JSON
// objects as base64url strings.
//
// # Symmetric provider
//
// NewSymmetric derives one AES-256-GCM key from a caller supplied secret with
// HKDF-SHA256 (RFC 5869, no salt, no info). Protect draws a fresh random
// 96-bit nonce from crypto/rand for every call and returns
//
//	nonce (SymmetricNonceSize = 12 bytes) || ciphertext || tag (SymmetricTagSize = 16 bytes)
//
// so a protected blob is SymmetricOverhead (28) bytes longer than the
// plaintext. No associated data is bound to the blob. Unprotect fails with an
// authentication error for a blob protected under another secret or modified
// in any byte (nonce, ciphertext or tag).
//
// # Secret material
//
// The secret is key material, not a password. HKDF only extracts and expands
// entropy that is already present (RFC 5869 §3.1): a low-entropy secret such
// as a passphrase yields a key that is as guessable as the passphrase, and
// HKDF gives it no brute-force resistance. Use at least SymmetricMinSecretSize
// (32) bytes from crypto/rand, or the output of a memory-hard password KDF
// (argon2id, scrypt) when the secret must be derived from a password. The
// size is documented, not enforced, so existing callers keep working.
//
// # Usage limits
//
// The nonce is random, so NIST SP 800-38D §8.3 applies: with a 96-bit random
// IV the number of Protect calls under one secret must not exceed 2^32
// (SymmetricMaxMessagesPerKey), which keeps the probability of a repeated
// nonce, and with it a loss of confidentiality and integrity, below 2^-32.
// Each plaintext must be shorter than 2^36 - 32 bytes (SP 800-38D §5.2.1.1,
// enforced by crypto/cipher, which panics beyond it); the helpers here are
// meant for small payloads.
//
// # Rotation
//
// A blob carries no key identifier or format version, so the package cannot
// tell which secret protected it. The caller owns rotation:
//
//   - record which secret protected each blob, for example with a key-id
//     prefix the caller manages, or by storing the blob next to a key id;
//   - keep a provider for every retired secret for as long as blobs protected
//     with it must be readable, and re-Protect a blob with the current secret
//     when it is read;
//   - retire a secret before its Protect count approaches
//     SymmetricMaxMessagesPerKey, and at once if it may have leaked.
//
// A versioned blob format with a key identifier is roadmap work; it would
// change the on-the-wire format and is not part of NewSymmetric (XPKI-083).
//
// References: NIST SP 800-38D (https://doi.org/10.6028/NIST.SP.800-38D),
// RFC 5869 (https://www.rfc-editor.org/rfc/rfc5869).
package dataprotection
