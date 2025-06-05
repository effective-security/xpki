package cryptoprov

import (
	"crypto"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

// NewSignerFromFromFile generates a new signer from a caFile
// and a caKey file, both PEM encoded or caKey contains PKCS#11 Uri
func (c *Crypto) NewSignerFromFromFile(caKeyFile string) (crypto.Signer, error) {
	cakey, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "load key file")
	}
	// remove trailing space and end-of-line
	cakey = []byte(strings.TrimSpace(string(cakey)))

	s, err := c.NewSignerFromPEM(cakey)
	if err != nil {
		return nil, errors.WithMessagef(err, "load key from file: %s", caKeyFile)
	}
	return s, nil
}

// NewSignerFromPEM generates a new crypto signer from PEM encoded blocks,
// or caKey contains PKCS#11 Uri
func (c *Crypto) NewSignerFromPEM(caKey []byte) (crypto.Signer, error) {
	_, pvk, err := c.LoadPrivateKey(caKey)
	if err != nil {
		return nil, err
	}

	signer, supported := pvk.(crypto.Signer)
	if !supported {
		return nil, errors.Errorf("loaded key of %T type does not support crypto.Signer", pvk)
	}

	return signer, nil
}
