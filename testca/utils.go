package testca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ToPFX wraps cert and its private key in a password-protected PKCS#12
// (PFX) packet encoded with pkcs12.Modern2023 (PBES2 with
// PBKDF2-HMAC-SHA-256 and AES-256-CBC, HMAC-SHA-256 MAC), readable by
// OpenSSL 1.1.1+, Java 12+ and Windows Server 2019+. The password may be
// empty and may contain any character of the Basic Multilingual Plane,
// since PKCS#12 encodes it as a BMPString (UCS-2); a character outside it,
// such as an emoji, cannot be encoded and panics (XPKI-063: the former
// OpenSSL-based implementation allowed alphanumeric passwords only). priv
// must be an *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey;
// anything else panics, as does an encoding failure.
func ToPFX(cert *x509.Certificate, priv any, password string) []byte {
	data, err := pkcs12.Modern2023.Encode(priv, cert, nil, password)
	if err != nil {
		panic(err)
	}
	return data
}

// ToPEM exports cert to PEM
func ToPEM(cert *x509.Certificate) []byte {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// ToDER exports private key to DER
func ToDER(priv any) []byte {
	var (
		der []byte
		err error
	)
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		der = x509.MarshalPKCS1PrivateKey(p)
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(p)
	default:
		err = errors.New("unknown key type")
	}
	if err != nil {
		panic(err)
	}

	return der
}

// PrivKeyToPEM exports private key to PEM
func PrivKeyToPEM(priv any) []byte {
	var (
		pemKey []byte
		err    error
	)
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(key)
		pemKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	case *ecdsa.PrivateKey:
		der, _ := x509.MarshalECPrivateKey(key)
		pemKey = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	default:
		err = errors.New("unknown key type")
	}
	if err != nil {
		panic(err)
	}

	return pemKey
}

// ToPKCS8 exports the private key as an unencrypted PKCS#8 PEM block
// ("PRIVATE KEY"), the same form `openssl pkcs8 -topk8 -nocrypt` produced
// (XPKI-063). priv must be an *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey; anything else panics.
func ToPKCS8(priv any) []byte {
	switch priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		panic(errors.New("unknown key type"))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
