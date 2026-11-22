package dpop

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
)

const (
	// NonceHTTPHeader is the response header that carries a server-provided
	// nonce (RFC 9449 §8). A response has at most one, and a response that
	// carries it should be uncacheable (Cache-Control: no-store).
	NonceHTTPHeader = "DPoP-Nonce"
	// ClaimNonce is the proof claim that carries the server-provided nonce.
	// Clients add it to the ForRequest extra claims:
	// map[string]any{dpop.ClaimNonce: nonce}.
	ClaimNonce = "nonce"
	// ErrorUseDPoPNonce is the OAuth error code of a response that asks the
	// client to retry with the nonce in the DPoP-Nonce header: an HTTP 400
	// error response from an authorization server (RFC 9449 §8), or an HTTP
	// 401 with UseDPoPNonceChallenge from a resource server (§9).
	ErrorUseDPoPNonce = "use_dpop_nonce"
	// UseDPoPNonceChallenge is the WWW-Authenticate value of a resource
	// server's HTTP 401 response that asks for a nonce (RFC 9449 §9).
	UseDPoPNonceChallenge = `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`
)

const (
	// DefaultNonceRotation is how often HMACNonceSource issues a new nonce
	// when HMACNonceConfig.Rotation is zero.
	DefaultNonceRotation = 5 * time.Minute
	// MinNonceRotation is the shortest HMACNonceConfig.Rotation.
	MinNonceRotation = time.Second
	// MaxNonceRotation is the longest HMACNonceConfig.Rotation: a nonce is
	// meant to limit the life of a proof to minutes (RFC 9449 §11.1).
	MaxNonceRotation = time.Hour
	// MinNonceSecretSize is the minimum size in bytes of every
	// HMACNonceConfig secret.
	MinNonceSecretSize = 32

	// nonceVersion is the first byte of a nonce, to tell later formats apart.
	nonceVersion byte = 1
	// nonceWindowSize is the size of the big-endian window number, and of
	// the big-endian rotation in nanoseconds in the MAC input.
	nonceWindowSize = 8
	// nonceMACSize is the size of the truncated HMAC-SHA256.
	nonceMACSize = 16
	// nonceSize is the size of a decoded nonce: version || window ||
	// HMAC-SHA256(secret, domain || 0 || label || 0 || rotation || window)[:16].
	nonceSize = 1 + nonceWindowSize + nonceMACSize
	// nonceDomain separates the nonce MAC from other uses of the secret.
	nonceDomain = "xpki/dpop/nonce/v1"
)

// ErrUseDPoPNonce is matched by errors.Is for a proof that VerifyClaims
// rejects because its nonce claim is missing, unknown or stale. The server
// answers with a fresh nonce in the DPoP-Nonce header and the
// ErrorUseDPoPNonce error code, and the client retries with that nonce.
var ErrUseDPoPNonce = errors.New("dpop: server nonce required")

// errNonceSourceNotInitialized is returned by an HMACNonceSource that was not
// created by NewHMACNonceSource.
var errNonceSourceNotInitialized = errors.New("dpop: nonce source is not initialized")

// nonceError is a nonce rejection: errors.Is matches it to ErrUseDPoPNonce,
// with the standard library and cockroachdb/errors alike, and its message is
// the reason only.
type nonceError struct {
	msg string
}

func (e *nonceError) Error() string { return e.msg }

// Is reports whether target is ErrUseDPoPNonce.
func (e *nonceError) Is(target error) bool { return target == ErrUseDPoPNonce }

// newNonceError returns a nonce rejection with a stack.
func newNonceError(msg string) error {
	return errors.WithStack(&nonceError{msg: msg})
}

// NonceSource issues the nonces of a server and checks the nonce claim of
// the proofs it receives (RFC 9449 §8 and §9). VerifyConfig.NonceSource
// makes VerifyClaims require a nonce from it. Implementations must be safe
// for concurrent use.
type NonceSource interface {
	// Nonce returns the nonce to send in the DPoP-Nonce header now: with
	// every use_dpop_nonce error, and in any other response when the
	// server wants the client to move to a new nonce early.
	Nonce(ctx context.Context) (string, error)
	// VerifyNonce returns nil when nonce is one that this source issued
	// recently. It returns an error that errors.Is matches to
	// ErrUseDPoPNonce when nonce is empty, unknown or stale, and any other
	// error when it cannot decide; VerifyClaims rejects the proof in both
	// cases.
	VerifyNonce(ctx context.Context, nonce string) error
}

// HMACNonceConfig configures NewHMACNonceSource.
type HMACNonceConfig struct {
	// Secrets are the HMAC keys, each at least MinNonceSecretSize bytes from
	// crypto/rand. The first issues nonces; every one is accepted. Every
	// instance of a server uses the same list. To rotate, append the new
	// secret on every instance, then move it first on every instance, and
	// remove the old one 2 * Rotation, plus the clock difference between the
	// instances, after the last instance moved it.
	Secrets [][]byte
	// Rotation is how often a new nonce is issued; zero means
	// DefaultNonceRotation, and it must be between MinNonceRotation and
	// MaxNonceRotation. It is part of the nonce MAC: every instance uses the
	// same value, and a change rejects the nonces in use once.
	Rotation time.Duration
	// Label keeps apart the nonces of servers that share secrets, such as
	// an authorization server and a resource server, whose nonces must not
	// be accepted by each other (RFC 9449 §9). Every instance of a server
	// uses the same label.
	Label string
}

// HMACNonceSource is a NonceSource that needs no store: a nonce is the
// number of the time window it was issued in, authenticated with
// HMAC-SHA256 under a secret that every instance of the server shares. All
// clients get the same nonce during a window: RFC 9449 leaves the scheme to
// the server (§8) and lets a nonce be used for more than one proof (§11.1),
// and the nonce cannot be predicted without the secret. A nonce is accepted in its
// own window and the next, so for at least Rotation and less than
// 2 * Rotation after it was issued; a nonce of the window after the current
// one, which an instance whose clock runs ahead issues, is accepted as
// well. The nonce bounds the age of a proof by the server's clock; the iat
// and exp claims are still checked. It uses TimeNowFn as its clock and is
// safe for concurrent use.
type HMACNonceSource struct {
	secrets  [][]byte
	rotation time.Duration
	label    []byte
}

// NewHMACNonceSource returns an HMACNonceSource for cfg. The secrets are
// copied.
func NewHMACNonceSource(cfg HMACNonceConfig) (*HMACNonceSource, error) {
	if len(cfg.Secrets) == 0 {
		return nil, errors.New("dpop: nonce secret is required")
	}
	secrets := make([][]byte, len(cfg.Secrets))
	for i, secret := range cfg.Secrets {
		if len(secret) < MinNonceSecretSize {
			return nil, errors.Errorf("dpop: nonce secret %d is shorter than %d bytes", i, MinNonceSecretSize)
		}
		secrets[i] = slices.Clone(secret)
	}
	rotation := cmp.Or(cfg.Rotation, DefaultNonceRotation)
	if rotation < MinNonceRotation {
		return nil, errors.Errorf("dpop: nonce rotation %s is shorter than %s", rotation, MinNonceRotation)
	}
	if rotation > MaxNonceRotation {
		return nil, errors.Errorf("dpop: nonce rotation %s is longer than %s", rotation, MaxNonceRotation)
	}
	return &HMACNonceSource{
		secrets:  secrets,
		rotation: rotation,
		label:    []byte(cfg.Label),
	}, nil
}

// Nonce returns the nonce of the current window; see NonceSource.
func (s *HMACNonceSource) Nonce(_ context.Context) (string, error) {
	if !s.initialized() {
		return "", errors.WithStack(errNonceSourceNotInitialized)
	}
	return s.encode(s.secrets[0], s.window(TimeNowFn())), nil
}

// VerifyNonce checks nonce; see NonceSource and HMACNonceSource.
func (s *HMACNonceSource) VerifyNonce(_ context.Context, nonce string) error {
	if !s.initialized() {
		return errors.WithStack(errNonceSourceNotInitialized)
	}
	if nonce == "" {
		return newNonceError("dpop: claim not found: nonce")
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != nonceSize || raw[0] != nonceVersion {
		return newNonceError("dpop: invalid nonce")
	}
	window := binary.BigEndian.Uint64(raw[1 : 1+nonceWindowSize])

	// compare the whole nonce, so that only the exact encoding is accepted
	known := false
	for _, secret := range s.secrets {
		if subtle.ConstantTimeCompare([]byte(s.encode(secret, window)), []byte(nonce)) == 1 {
			known = true
		}
	}
	if !known {
		return newNonceError("dpop: invalid nonce")
	}

	current := s.window(TimeNowFn())
	switch {
	case window+1 < current:
		return newNonceError("dpop: nonce expired")
	case window > current+1:
		return newNonceError("dpop: nonce is not valid yet")
	}
	return nil
}

// initialized reports whether s was created by NewHMACNonceSource.
func (s *HMACNonceSource) initialized() bool {
	return s != nil && len(s.secrets) > 0 && s.rotation > 0
}

// window returns the number of the window that contains t.
func (s *HMACNonceSource) window(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(s.rotation))
}

// encode returns the nonce of window under secret.
func (s *HMACNonceSource) encode(secret []byte, window uint64) string {
	raw := make([]byte, 1+nonceWindowSize, nonceSize)
	raw[0] = nonceVersion
	binary.BigEndian.PutUint64(raw[1:], window)

	// the label is the only field of variable length, and it ends before
	// the fixed-size rotation and window
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(nonceDomain))
	mac.Write([]byte{0})
	mac.Write(s.label)
	mac.Write([]byte{0})
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(s.rotation)))
	mac.Write(raw[1:])
	raw = mac.Sum(raw)[:nonceSize]
	return base64.RawURLEncoding.EncodeToString(raw)
}
