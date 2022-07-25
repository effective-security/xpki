package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
)

// KeyInfo provides information about the key
type KeyInfo struct {
	KeySize   int
	Type      string
	IsPrivate bool
	Hash      crypto.Hash
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
		ki.Hash = hashAlgo(typ.Public)
		return ki, nil
	case *ecdsa.PrivateKey:
		ki.Type = "ECDSA"
		ki.IsPrivate = true
		ki.KeySize = typ.Curve.Params().BitSize
		ki.Hash = hashAlgo(typ.Public)
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
	ki.Hash = hashAlgo(pubKey)
	return ki, nil
}

func hashAlgo(pub crypto.PublicKey) crypto.Hash {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		switch {
		case keySize >= 4096:
			return crypto.SHA512
		case keySize >= 3072:
			return crypto.SHA384
		case keySize >= 2048:
			return crypto.SHA256
		default:
			return crypto.SHA1
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return crypto.SHA256
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		default:
			return crypto.SHA1
		}
	default:
		return crypto.SHA1
	}
}
