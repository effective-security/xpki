package cryptoprov

import (
	"context"
	"crypto"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

// NewSignerFromFromFile returns the signer of the key in caKeyFile, which
// holds a PEM encoded key or a PKCS#11 URI; ctx is for the URI, see
// LoadPrivateKey.
func (c *Crypto) NewSignerFromFromFile(ctx context.Context, caKeyFile string) (crypto.Signer, error) {
	cakey, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "load key file")
	}
	// remove trailing space and end-of-line
	cakey = []byte(strings.TrimSpace(string(cakey)))

	s, err := c.NewSignerFromPEM(ctx, cakey)
	if err != nil {
		return nil, errors.WithMessagef(err, "load key from file: %s", caKeyFile)
	}
	return s, nil
}

// NewSignerFromPEM returns the signer of caKey, a PEM encoded key or a
// PKCS#11 URI; ctx is for the URI, see LoadPrivateKey.
func (c *Crypto) NewSignerFromPEM(ctx context.Context, caKey []byte) (crypto.Signer, error) {
	_, pvk, err := c.LoadPrivateKey(ctx, caKey)
	if err != nil {
		return nil, err
	}

	signer, supported := pvk.(crypto.Signer)
	if !supported {
		return nil, errors.Errorf("loaded key of %T type does not support crypto.Signer", pvk)
	}

	return signer, nil
}
