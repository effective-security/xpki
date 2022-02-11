package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

// KeyInfo provides information about the key
type KeyInfo struct {
	KeySize   int
	Type      string
	IsPrivate bool
	Key       interface{}
}

// NewKeyInfo returns *SignerInfo
func NewKeyInfo(k interface{}) (*KeyInfo, error) {
	ki := &KeyInfo{Key: k}
	var pubKey crypto.PublicKey

	// find the Public
	switch typ := k.(type) {
	case *rsa.PrivateKey:
		ki.KeySize = typ.N.BitLen()
		ki.IsPrivate = true
		ki.Type = "RSA"
		return ki, nil
	case *ecdsa.PrivateKey:
		ki.Type = "ECDSA"
		ki.IsPrivate = true
		ki.KeySize = typ.Curve.Params().BitSize
		return ki, nil
	case crypto.Signer:
		pubKey = typ.Public()
	case crypto.Decrypter:
		pubKey = typ.Public()
	case *jose.JSONWebKey:
		return NewKeyInfo(typ.Key)
	default:
		pubKey = k
	}

	switch typ := pubKey.(type) {
	case *rsa.PublicKey:
		ki.KeySize = typ.N.BitLen()
		ki.Type = "RSA"
	case *ecdsa.PublicKey:
		ki.Type = "ECDSA"
		ki.KeySize = typ.Curve.Params().BitSize
	default:
		return nil, errors.Errorf("key not supported: %T", typ)
	}
	return ki, nil
}
