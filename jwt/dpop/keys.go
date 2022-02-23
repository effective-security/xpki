package dpop

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

// Thumbprint returns key thumbprint
func Thumbprint(k *jose.JSONWebKey) (string, error) {
	tb, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Errorf("dpop: unable to get thumprint")
	}
	return base64.RawURLEncoding.EncodeToString(tb), nil
}

// LoadKey returns *jose.JSONWebKey
func LoadKey(path string) (*jose.JSONWebKey, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", errors.WithStack(err)
	}
	k := new(jose.JSONWebKey)
	err = json.Unmarshal(b, k)
	if err != nil {
		return nil, "", errors.WithStack(err)
	}
	dpopThumbprint, err := Thumbprint(k)
	if err != nil {
		return nil, "", errors.WithStack(err)
	}

	return k, dpopThumbprint, nil
}

// SaveKey saves the key to storage
func SaveKey(folder string, k *jose.JSONWebKey) (string, error) {
	err := os.MkdirAll(folder, 0700)
	if err != nil {
		logger.KV(xlog.WARNING,
			"reason", "create_storage_folder",
			"folder", folder,
			"err", err,
		)
		// DO NOT return error, as file save can fail
	}
	dpopThumbprint, err := Thumbprint(k)
	if err != nil {
		return "", errors.WithStack(err)
	}

	fn := path.Join(folder, dpopThumbprint+".jwk.key")
	fullData, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return "", errors.WithStack(err)
	}
	err = os.WriteFile(fn, fullData, 0600)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to save key")
	}
	return fn, nil
}
