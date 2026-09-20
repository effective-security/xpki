package cryptoprov

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

// LoadPrivateKey returns crypto.PrivateKey.
// The input key can be in PEM encoded format, or PKCS11 URI.
func (c *Crypto) LoadPrivateKey(key []byte) (Provider, crypto.PrivateKey, error) {
	var err error
	var pvk crypto.PrivateKey
	var provider Provider

	keyPem := string(key)
	if strings.HasPrefix(keyPem, "pkcs11") {
		pkuri, err := ParsePrivateKeyURI(keyPem)
		if err != nil {
			return nil, nil, errors.WithMessage(err, "failed to parse key")
		}

		provider, err = c.ByManufacturer(pkuri.Manufacturer(), pkuri.Model())
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "provider not found: %s model: %s",
				pkuri.Manufacturer(), pkuri.Model())
		}

		pvk, err = provider.GetKey(pkuri.ID())
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "unable to get key: %s", pkuri.ID())
		}
	} else {
		pvk, err = ParsePrivateKeyPEM(key)
		if err != nil {
			return nil, nil, errors.WithMessage(err, "failed to parse key")
		}
	}

	return provider, pvk, nil
}

// ParsePrivateKeyPEM parses and returns a PEM-encoded private
// key. The private key may be either an unencrypted PKCS#8, PKCS#1,
// or elliptic private key.
func ParsePrivateKeyPEM(keyPEM []byte) (key crypto.PrivateKey, err error) {
	return ParsePrivateKeyPEMWithPassword(keyPEM, nil)
}

// ParsePrivateKeyPEMWithPassword parses and returns a PEM-encoded private
// key. The private key may be an unencrypted PKCS#8, PKCS#1, or SEC1 key,
// or a legacy PEM block encrypted per RFC 1423 (Proc-Type: 4,ENCRYPTED);
// encrypted PKCS#8 (ENCRYPTED PRIVATE KEY) is not supported. The key may be
// RSA or ECDSA.
func ParsePrivateKeyPEMWithPassword(keyPEM []byte, password []byte) (key crypto.PrivateKey, err error) {
	keyDER, err := GetPrivateKeyDERFromPEM(keyPEM, password)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyDER(keyDER)
}

// GetPrivateKeyDERFromPEM parses a PEM-encoded private key and
// returns DER-format key bytes.
func GetPrivateKeyDERFromPEM(in []byte, password []byte) ([]byte, error) {
	// Ignore any EC PARAMETERS blocks when looking for a key (openssl includes
	// them by default).
	var keyDER *pem.Block
	for {
		keyDER, in = pem.Decode(in)
		if keyDER == nil || keyDER.Type != "EC PARAMETERS" {
			break
		}
	}
	if keyDER != nil {
		if procType, ok := keyDER.Headers["Proc-Type"]; ok {
			if strings.Contains(procType, "ENCRYPTED") {
				if password != nil {
					return x509.DecryptPEMBlock(keyDER, password) //nolint:staticcheck
				}
				return nil, errors.Errorf("private key is encrypted")
			}
		}
		return keyDER.Bytes, nil
	}

	return nil, errors.Errorf("unable to decode private key")
}

// ParsePrivateKeyDER parses a PKCS #1, PKCS #8, ECDSA DER-encoded
// private key. The key must not be in PEM format.
func ParsePrivateKeyDER(keyDER []byte) (crypto.PrivateKey, error) {
	generalKey, pkcs8Err := x509.ParsePKCS8PrivateKey(keyDER)
	if pkcs8Err != nil {
		var pkcs1Err error
		generalKey, pkcs1Err = x509.ParsePKCS1PrivateKey(keyDER)
		if pkcs1Err != nil {
			var ecErr error
			generalKey, ecErr = x509.ParseECPrivateKey(keyDER)
			if ecErr != nil {
				return nil, errors.WithMessage(errors.Join(pkcs8Err, pkcs1Err, ecErr), "failed to parse key")
			}
		}
	}

	switch typ := generalKey.(type) {
	case *rsa.PrivateKey:
		return typ, nil
	case *ecdsa.PrivateKey:
		return typ, nil
	case ed25519.PrivateKey:
		return typ, nil
	}

	return nil, errors.Errorf("failed to parse key: unsupported key type %T", generalKey)
}

// LoadTLSKeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf holds
// the parsed leaf certificate.
func (c *Crypto) LoadTLSKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return c.TLSKeyPair(certPEMBlock, keyPEMBlock)
}

// TLSKeyPair parses a public/private key pair from PEM encoded data. The key
// may be a PEM private key or a pkcs11: URI resolved through the registered
// providers. On successful return, Certificate.Leaf holds the parsed leaf
// certificate. An error is returned when the private key does not match
// the leaf certificate's public key.
func (c *Crypto) TLSKeyPair(certPEMBlock, keyPEMBlock []byte) (*tls.Certificate, error) {
	var err error
	var skippedBlockTypes []string

	cert := &tls.Certificate{}

	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.New("tls: failed to find any PEM data in certificate input")
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched")
		}
		return nil, errors.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
	}

	// The leaf is parsed so that callers get Certificate.Leaf and so that
	// the private key can be checked against the certificate.
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	_, cert.PrivateKey, err = c.LoadPrivateKey(keyPEMBlock)
	if err != nil {
		return nil, err
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.Errorf("tls: private key of type %T does not implement crypto.Signer", cert.PrivateKey)
	}
	pub, ok := cert.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, errors.Errorf("tls: unsupported certificate public key type %T", cert.Leaf.PublicKey)
	}
	if !pub.Equal(signer.Public()) {
		return nil, errors.New("tls: private key does not match certificate public key")
	}

	return cert, nil
}
