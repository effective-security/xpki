// Package dataprotection provides authenticated encryption of small payloads
// behind the Provider interface, plus helpers to protect and unprotect JSON
// objects as base64url strings. NewSymmetric derives an AES-256-GCM key from
// a caller supplied high-entropy secret with HKDF-SHA256; the protected blob
// is nonce || ciphertext || tag with no key identifier, so key rotation must
// be handled by the caller.
package dataprotection
