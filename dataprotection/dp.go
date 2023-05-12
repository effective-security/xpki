package dataprotection

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// Provider interface for data protection
type Provider interface {
	// Protect returns protected blob
	Protect(ctx context.Context, data []byte) ([]byte, error)
	// Unprotect returns unprotected data
	Unprotect(ctx context.Context, protected []byte) ([]byte, error)
	// IsReady returns true when provider has encryption keys
	IsReady() bool
}

// ProtectStruct returns encrypted object value in base64url encoded format
func ProtectObject(ctx context.Context, p Provider, v interface{}) (string, error) {
	js, err := json.Marshal(v)
	if err != nil {
		return "", errors.WithMessage(err, "failed to marshal")
	}
	ejs, err := p.Protect(ctx, js)
	if err != nil {
		return "", errors.WithMessage(err, "failed to protect")
	}
	return base64.RawURLEncoding.EncodeToString(ejs), nil
}

// UnprotectObject decrypts and unmarshals protected Base64 encoded string to a struct
func UnprotectObject(ctx context.Context, p Provider, protected string, v interface{}) error {
	js, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return errors.WithMessage(err, "failed to base64 decode")
	}
	js, err = p.Unprotect(ctx, js)
	if err != nil {
		return errors.WithMessage(err, "failed to unprotect data")
	}

	if err = json.Unmarshal(js, v); err != nil {
		return errors.WithMessage(err, "failed to unmarshal")
	}
	return nil
}
