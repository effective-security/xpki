package certutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
)

// LoadFromPEM returns Certificate loaded from the file
func LoadFromPEM(certFile string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cert, err := ParseFromPEM(bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ParseFromPEM returns Certificate parsed from PEM
func ParseFromPEM(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.Errorf("unable to parse PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to parse certificate")
	}

	return cert, nil
}

// LoadChainFromPEM returns Certificates loaded from the file
func LoadChainFromPEM(certFile string) ([]*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	certs, err := ParseChainFromPEM(bytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// ParseChainFromPEM returns Certificates parsed from PEM
func ParseChainFromPEM(certificateChainPem []byte) ([]*x509.Certificate, error) {
	list := make([]*x509.Certificate, 0)
	var block *pem.Block
	// trim white space around PEM
	rest := []byte(strings.TrimSpace(string(certificateChainPem)))
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return list, errors.Errorf("potentially malformed PEM")
		}
		if block.Type == "CERTIFICATE" {
			x509Certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.WithMessage(err, "failed to parse certificate")
			}
			list = append(list, x509Certificate)
		}
		rest = []byte(strings.TrimSpace(string(rest)))
	}
	return list, nil
}

// encodeToPEM converts certificate to PEM format, with optional comments
func encodeToPEM(out io.Writer, withComments bool, crt *x509.Certificate) error {
	if withComments {
		fmt.Fprintf(out, "#   Issuer: %s", NameToString(&crt.Issuer))
		fmt.Fprintf(out, "\n#   Subject: %s", NameToString(&crt.Subject))
		fmt.Fprint(out, "\n#   Validity")
		fmt.Fprintf(out, "\n#       Not Before: %s", crt.NotBefore.UTC().Format(certTimeFormat))
		fmt.Fprintf(out, "\n#       Not After : %s", crt.NotAfter.UTC().Format(certTimeFormat))
		fmt.Fprint(out, "\n")
	}

	err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// EncodeToPEM converts certificates to PEM format, with optional comments
func EncodeToPEM(out io.Writer, withComments bool, certs ...*x509.Certificate) error {
	for _, crt := range certs {
		if crt != nil {
			err := encodeToPEM(out, withComments, crt)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// EncodeToPEMString converts certificates to PEM format, with optional comments
func EncodeToPEMString(withComments bool, certs ...*x509.Certificate) (string, error) {
	if len(certs) == 0 || certs[0] == nil {
		return "", nil
	}

	b := bytes.NewBuffer([]byte{})
	err := EncodeToPEM(b, withComments, certs...)
	if err != nil {
		return "", err
	}
	pem := b.String()
	pem = strings.TrimSpace(pem)
	pem = strings.Replace(pem, "\n\n", "\n", -1)
	return pem, nil
}

// CreatePoolFromPEM returns CertPool from PEM encoded certs
func CreatePoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	certs, err := ParseChainFromPEM(pemBytes)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool, nil
}

// LoadPEMFiles loads and concantenates PEM files into one slice
func LoadPEMFiles(files ...string) ([]byte, error) {
	var pem []byte
	for _, f := range files {
		if f == "" {
			continue
		}
		b, err := ioutil.ReadFile(f)
		if err != nil {
			return pem, errors.WithMessage(err, "failed to load PEM")
		}
		s := bytes.TrimSpace(b)
		if len(s) == 0 {
			continue
		}

		if len(pem) > 0 {
			pem = append(pem, byte('\n'))
			pem = append(pem, s...)
		} else {
			pem = s
		}

	}
	return pem, nil
}

// JoinPEM returns concantenated PEM
func JoinPEM(p1, p2 []byte) []byte {
	p1 = bytes.TrimSpace(p1)
	if len(p2) > 0 {
		if len(p1) > 0 {
			p1 = append(p1, '\n')
		}
		p1 = append(p1, bytes.TrimSpace(p2)...)
	}
	return p1
}

// ParseRSAPublicKeyFromPEM parses PEM encoded RSA public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("key must be PEM encoded")
	}

	// Parse the key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if _, err = asn1.Unmarshal(block.Bytes, &parsedKey); err != nil {
			return nil, errors.New("unable to parse RSA Public Key")
		}
	}

	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA Public Key")
	}

	return pkey, nil
}

// EncodePublicKeyToPEM returns PEM encoded public key
func EncodePublicKeyToPEM(pubKey crypto.PublicKey) ([]byte, error) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	b := bytes.NewBuffer([]byte{})

	err = pem.Encode(b, pemkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return b.Bytes(), nil
}

// EncodePrivateKeyToPEM returns PEM encoded private key
func EncodePrivateKeyToPEM(priv crypto.PrivateKey) (key []byte, err error) {
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		key = x509.MarshalPKCS1PrivateKey(priv)
		block := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	case *ecdsa.PrivateKey:
		key, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		block := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	default:
		return nil, errors.Errorf("unsupported key: %T", priv)
	}

	return
}

// ParsePrivateKeyPEM parses and returns a PEM-encoded private
// key. The private key may be either an unencrypted PKCS#8, PKCS#1,
// or elliptic private key.
func ParsePrivateKeyPEM(keyPEM []byte) (key crypto.Signer, err error) {
	return ParsePrivateKeyPEMWithPassword(keyPEM, nil)
}

// ParsePrivateKeyPEMWithPassword parses and returns a PEM-encoded private
// key. The private key may be a potentially encrypted PKCS#8, PKCS#1,
// or elliptic private key.
func ParsePrivateKeyPEMWithPassword(keyPEM []byte, password []byte) (key crypto.Signer, err error) {
	keyDER, err := GetKeyDERFromPEM(keyPEM, password)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKeyDER(keyDER)
}

// GetKeyDERFromPEM parses a PEM-encoded private key and returns DER-format key bytes.
func GetKeyDERFromPEM(in []byte, password []byte) ([]byte, error) {
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
					return x509.DecryptPEMBlock(keyDER, password)
				}
				return nil, errors.Errorf("encrypted private key")
			}
		}
		return keyDER.Bytes, nil
	}

	return nil, errors.Errorf("unable to decode private key")
}

// ParsePrivateKeyDER parses a PKCS #1, PKCS #8, ECDSA, or Ed25519 DER-encoded
// private key. The key must not be in PEM format.
func ParsePrivateKeyDER(keyDER []byte) (key crypto.Signer, err error) {
	generalKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		generalKey, err = x509.ParsePKCS1PrivateKey(keyDER)
		if err != nil {
			generalKey, err = x509.ParseECPrivateKey(keyDER)
			// TODO:
			//generalKey, err = ParseEd25519PrivateKey(keyDER)
			if err != nil {
				// We don't include the actual error into
				// the final error. The reason might be
				// we don't want to leak any info about
				// the private key.
				return nil, errors.Errorf("unable to parse private key")
			}
		}
	}

	switch generalKey.(type) {
	case *rsa.PrivateKey:
		return generalKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return generalKey.(*ecdsa.PrivateKey), nil
	case ed25519.PrivateKey:
		return generalKey.(ed25519.PrivateKey), nil
	}

	// should never reach here
	return nil, errors.Errorf("unable to parse private key")
}
