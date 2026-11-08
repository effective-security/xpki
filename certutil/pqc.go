package certutil

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
)

// Key type names reported by KeyInfo.Type, as crypto/x509 prints the
// public key algorithm.
const (
	// KeyTypeRSA is the KeyInfo.Type of an RSA key.
	KeyTypeRSA = "RSA"
	// KeyTypeECDSA is the KeyInfo.Type of an ECDSA key.
	KeyTypeECDSA = "ECDSA"
	// KeyTypeMLDSA is the KeyInfo.Type of an ML-DSA (FIPS 204) key.
	KeyTypeMLDSA = "ML-DSA"
)

// FIPS 204 parameter set numbers, as KeyInfo.KeySize reports them for an
// ML-DSA key.
const (
	mldsa44 = 44
	mldsa65 = 65
	mldsa87 = 87
)

// mldsaParameterSetNumber returns the FIPS 204 number of params, 44, 65 or
// 87, and 0 for a parameter set this module does not know.
func mldsaParameterSetNumber(params mldsa.Parameters) int {
	switch params {
	case mldsa.MLDSA44():
		return mldsa44
	case mldsa.MLDSA65():
		return mldsa65
	case mldsa.MLDSA87():
		return mldsa87
	default:
		return 0
	}
}

// IsPostQuantumKey reports whether key is a post-quantum (ML-DSA) key: an
// *mldsa.PublicKey or *mldsa.PrivateKey, or a crypto.Signer or
// crypto.Decrypter, such as an HSM or KMS key, whose Public() is one. A nil
// key is not post-quantum.
func IsPostQuantumKey(key any) bool {
	switch typ := key.(type) {
	case *mldsa.PublicKey:
		return typ != nil
	case *mldsa.PrivateKey:
		return typ != nil
	case crypto.Signer:
		return isMLDSAPublicKey(typ.Public())
	case crypto.Decrypter:
		return isMLDSAPublicKey(typ.Public())
	default:
		return false
	}
}

func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	key, ok := pub.(*mldsa.PublicKey)
	return ok && key != nil
}

// IsPostQuantumSignatureAlgorithm reports whether algo is a post-quantum
// X.509 signature algorithm: ML-DSA-44, ML-DSA-65 or ML-DSA-87.
func IsPostQuantumSignatureAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return true
	default:
		return false
	}
}

// IsPostQuantumCertificate reports whether crt carries a post-quantum
// public key or is signed with a post-quantum signature algorithm, so a
// chain that mixes classical and ML-DSA keys is detected at either end. A
// nil certificate is not post-quantum.
func IsPostQuantumCertificate(crt *x509.Certificate) bool {
	if crt == nil {
		return false
	}
	return crt.PublicKeyAlgorithm == x509.MLDSA || IsPostQuantumSignatureAlgorithm(crt.SignatureAlgorithm)
}
