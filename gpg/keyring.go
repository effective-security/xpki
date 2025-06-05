package gpg

import (
	"bytes"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/armor"
	"golang.org/x/crypto/openpgp"
)

// KeyRing reads a openpgp.KeyRing from the given io.Reader which may then be
// used to validate GPG keys in RPM packages.
func KeyRing(data []byte) (openpgp.EntityList, error) {
	keyring := make(openpgp.EntityList, 0)

	for {
		block, rest := armor.Decode(data)
		if block == nil {
			logger.KV(xlog.TRACE, "reason", "no_block", "data", string(data))
			break
		}

		if block.Type == openpgp.PublicKeyType {
			// extract keys
			el, err := openpgp.ReadKeyRing(bytes.NewReader(block.Bytes))
			if err != nil {
				return nil, errors.WithStack(err)
			}
			// append keyring
			keyring = append(keyring, el...)
		}
		if len(rest) == 0 {
			break
		}
		data = rest
	}

	return keyring, nil
}

// KeyRingFromFile reads a openpgp.KeyRing from the given file path which may
// then be used to validate GPG keys in RPM packages.
func KeyRingFromFile(path string) (openpgp.EntityList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	k, err := KeyRing(data)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// KeyRingFromFiles reads a openpgp.KeyRing from the given file paths which may
// then be used to validate GPG keys in RPM packages.
//
// This function might typically be used to read all keys in /etc/pki/rpm-gpg.
func KeyRingFromFiles(files []string) (openpgp.EntityList, error) {
	keyring := make(openpgp.EntityList, 0)
	for _, path := range files {
		// read keyring in file
		el, err := KeyRingFromFile(path)
		if err != nil {
			return nil, err
		}

		// append keyring
		keyring = append(keyring, el...)
	}

	return keyring, nil
}
