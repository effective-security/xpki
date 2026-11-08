package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"

	"github.com/cockroachdb/errors"
	"github.com/go-jose/go-jose/v4"
)

// KeyInfo provides information about the key: Type is KeyTypeRSA,
// KeyTypeECDSA or KeyTypeMLDSA; KeySize is the RSA modulus or ECDSA curve
// size in bits, or the ML-DSA parameter set number (44, 65 or 87); Hash is
// the digest a hash-then-sign caller uses with the key, and zero for an
// ML-DSA key, which signs the message itself.
type KeyInfo struct {
	KeySize   int
	Type      string
	IsPrivate bool
	Hash      crypto.Hash
	Key       any
}

// NewKeyInfo returns the KeyInfo of k: an RSA, ECDSA or ML-DSA private key,
// public key, crypto.Signer or crypto.Decrypter (an HSM or KMS key, whose
// Public() is inspected) or a JWK holding one of them. IsPrivate is set
// only for an in-memory private key.
func NewKeyInfo(k any) (*KeyInfo, error) {
	ki := &KeyInfo{Key: k}
	var pubKey crypto.PublicKey

	// find the Public
	switch typ := k.(type) {
	case *rsa.PrivateKey:
		ki.KeySize = typ.N.BitLen()
		ki.IsPrivate = true
		ki.Type = KeyTypeRSA
		ki.Hash = hashAlgo(typ.Public())
		return ki, nil
	case *ecdsa.PrivateKey:
		ki.Type = KeyTypeECDSA
		ki.IsPrivate = true
		ki.KeySize = typ.Curve.Params().BitSize
		ki.Hash = hashAlgo(typ.Public())
		return ki, nil
	case *mldsa.PrivateKey:
		pub := typ.PublicKey()
		ki.Type = KeyTypeMLDSA
		ki.IsPrivate = true
		ki.KeySize = mldsaParameterSetNumber(pub.Parameters())
		ki.Hash = hashAlgo(pub)
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
		ki.Type = KeyTypeRSA
	case *ecdsa.PublicKey:
		ki.Type = KeyTypeECDSA
		ki.KeySize = typ.Curve.Params().BitSize
	case *mldsa.PublicKey:
		ki.Type = KeyTypeMLDSA
		ki.KeySize = mldsaParameterSetNumber(typ.Parameters())
	default:
		return nil, errors.Errorf("key not supported: %T", typ)
	}
	ki.Hash = hashAlgo(pubKey)
	return ki, nil
}

// hashAlgo returns the digest a hash-then-sign caller uses with pub, and
// zero for an ML-DSA key, which signs the message.
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
	case *mldsa.PublicKey:
		return crypto.Hash(0)
	default:
		return crypto.SHA1
	}
}
