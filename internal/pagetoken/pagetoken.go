package pagetoken

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"

	"github.com/cockroachdb/errors"
)

const (
	// version is the envelope format; a token of another version is invalid.
	version = 1

	// bindingSize is the number of hash bytes kept in a token. The binding
	// detects a token reused with another request; it is not a MAC.
	bindingSize = 8

	// MaxTokenSize is the longest token Decode accepts, so a caller-supplied
	// string cannot make it decode an arbitrarily large document.
	MaxTokenSize = 8 << 10
)

// ErrInvalid is the cause of every Decode failure: a token that is not one,
// has another version or was issued for another binding.
var ErrInvalid = errors.New("invalid page token")

// envelope is the JSON document a token encodes.
type envelope struct {
	Version int             `json:"v"`
	Binding []byte          `json:"b"`
	Payload json.RawMessage `json:"p"`
}

// Binding returns the binding of v: a hash of its JSON encoding. v must
// marshal deterministically, which structs, sorted slices and maps (whose
// keys encoding/json sorts) do.
func Binding(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to encode page token binding")
	}
	sum := sha256.Sum256(data)
	return sum[:bindingSize], nil
}

// Encode returns the token that carries payload for binding.
func Encode(binding []byte, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", errors.WithMessage(err, "unable to encode page token")
	}
	token, err := json.Marshal(envelope{
		Version: version,
		Binding: binding,
		Payload: data,
	})
	if err != nil {
		return "", errors.WithMessage(err, "unable to encode page token")
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Decode reads the payload of token into payload, which must be a pointer.
// It fails with a wrapped ErrInvalid when token is malformed, too long, of
// another version or was issued for another binding.
func Decode(binding []byte, token string, payload any) error {
	if len(token) > MaxTokenSize {
		return errors.Wrapf(ErrInvalid, "token of %d bytes is too long", len(token))
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return errors.Wrap(ErrInvalid, "not base64url")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return errors.Wrap(ErrInvalid, "not a token")
	}
	if env.Version != version {
		return errors.Wrapf(ErrInvalid, "unsupported version %d", env.Version)
	}
	if subtle.ConstantTimeCompare(env.Binding, binding) != 1 {
		return errors.Wrap(ErrInvalid, "issued for another request")
	}
	if err := json.Unmarshal(env.Payload, payload); err != nil {
		return errors.Wrap(ErrInvalid, "unexpected payload")
	}
	return nil
}
