package dataprotection

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// rfc5869Case3OKM is the output keying material of RFC 5869 A.3
	// (HKDF-SHA256, 22 bytes of 0x0b as input keying material, no salt, no
	// info, 42 bytes).
	rfc5869Case3OKM = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
	// fipsChildEnv marks the re-executed test binary that runs
	// TestNewSymmetricFIPS140Only under GODEBUG=fips140=only.
	fipsChildEnv = "XPKI_DATAPROTECTION_FIPS_CHILD"
)

func TestNewSymmetric(t *testing.T) {
	p, err := NewSymmetric([]byte("secret"))
	require.NoError(t, err)
	assert.True(t, p.IsReady())
	assert.Nil(t, p.PublicKey())

	plaintext := []byte(`small data`)
	ctx := context.Background()
	protected, err := p.Protect(ctx, plaintext)
	require.NoError(t, err)

	unprotected, err := p.Unprotect(ctx, protected)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unprotected)

	// modify the data: flip one bit of the authentication tag, then one bit
	// of the nonce (XPKI-106: copying one random nonce byte over another
	// left the input unchanged when the bytes were equal)
	tampered := slices.Clone(protected)
	tampered[len(tampered)-1] ^= 0x01
	require.NotEqual(t, protected, tampered)
	_, err = p.Unprotect(ctx, tampered)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")

	tampered = slices.Clone(protected)
	tampered[0] ^= 0x80
	require.NotEqual(t, protected, tampered)
	_, err = p.Unprotect(ctx, tampered)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")

	_, err = p.Unprotect(ctx, nil)
	assert.EqualError(t, err, "invalid data: less than nonce size")

	_, err = p.Unprotect(ctx, protected[:11])
	assert.EqualError(t, err, "invalid data: less than nonce size")

	s := state{Str: "hello", ID: 123}
	b64, err := ProtectObject(ctx, p, s)
	require.NoError(t, err)
	var s2 state
	err = UnprotectObject(ctx, p, b64, &s2)
	require.NoError(t, err)
	assert.Equal(t, s, s2)

	err = UnprotectObject(ctx, p, "b64", &s2)
	assert.EqualError(t, err, "invalid data: less than nonce size")

	err = UnprotectObject(ctx, p, "Aa"+b64, &s2)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")
}

// TestNewSymmetricKnownAnswer pins the key derivation to RFC 5869 test case 3
// (HKDF-SHA256, no salt, no info): a blob sealed with the first 32 bytes of
// its output opens with NewSymmetric(input), and the reverse. Blobs protected
// by earlier releases stay readable only while this key stays the same.
func TestNewSymmetricKnownAnswer(t *testing.T) {
	t.Parallel()

	okm, err := hex.DecodeString(rfc5869Case3OKM)
	require.NoError(t, err)
	block, err := aes.NewCipher(okm[:32])
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	p, err := NewSymmetric(bytes.Repeat([]byte{0x0b}, 22))
	require.NoError(t, err)
	ctx := context.Background()
	plaintext := []byte("RFC 5869 A.3")

	nonce := make([]byte, SymmetricNonceSize)
	got, err := p.Unprotect(ctx, gcm.Seal(slices.Clone(nonce), nonce, plaintext, nil))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	protected, err := p.Protect(ctx, plaintext)
	require.NoError(t, err)
	got, err = gcm.Open(nil, protected[:SymmetricNonceSize], protected[SymmetricNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestNewSymmetricFIPS140Only checks that NewSymmetric returns an error, and
// does not panic, in a process run with GODEBUG=fips140=only. The standard
// library refuses GCM with caller-chosen nonces in that mode, so the provider
// is not available there (XPKI-132); crypto/hkdf refuses a secret shorter than
// 112 bits before that.
func TestNewSymmetricFIPS140Only(t *testing.T) {
	if os.Getenv(fipsChildEnv) != "" {
		_, err := NewSymmetric([]byte("secret"))
		assert.EqualError(t, err, "unable to derive key: crypto/hkdf: use of keys shorter than 112 bits is not allowed in FIPS 140-only mode")
		_, err = NewSymmetric(make([]byte, SymmetricMinSecretSize))
		assert.EqualError(t, err, "crypto/cipher: use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce")
		return
	}
	t.Parallel()

	cmd := exec.Command(os.Args[0], "-test.run=^TestNewSymmetricFIPS140Only$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), fipsChildEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Contains(t, string(out), "--- PASS: TestNewSymmetricFIPS140Only")
}

type state struct {
	Str string `json:"str,omitempty"`
	ID  uint64 `json:"id,omitempty"`
}
