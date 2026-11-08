package csr

import (
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/x509"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
)

// KeyRequest algorithm names; Algo is matched case-insensitively.
const (
	// AlgoRSA requests an RSA key of Size bits (2048 to 4096).
	AlgoRSA = "RSA"
	// AlgoECDSA requests an ECDSA key on the curve of Size bits (CurveP256,
	// CurveP384 or CurveP521).
	AlgoECDSA = "ECDSA"
	// AlgoMLDSA requests an ML-DSA (FIPS 204) key of the parameter set
	// Size: MLDSA44, MLDSA65 or MLDSA87. The spelling "MLDSA" is accepted
	// too.
	AlgoMLDSA = "ML-DSA"

	// algoMLDSAAlias is the spelling of AlgoMLDSA without the hyphen.
	algoMLDSAAlias = "MLDSA"
)

const (
	// CurveP256 specifies curve P-256 for ECDSA
	CurveP256 = 256

	// CurveP384 specifies curve P-384 for ECDSA
	CurveP384 = 384

	// CurveP521 specifies curve P-521 for ECDSA
	CurveP521 = 521

	// MLDSA44 specifies the ML-DSA-44 parameter set
	MLDSA44 = cryptoprov.MLDSA44

	// MLDSA65 specifies the ML-DSA-65 parameter set
	MLDSA65 = cryptoprov.MLDSA65

	// MLDSA87 specifies the ML-DSA-87 parameter set
	MLDSA87 = cryptoprov.MLDSA87
)

// KeyPurpose declares the purpose for keys
type KeyPurpose int

const (
	// Undefined purpose of key
	Undefined KeyPurpose = 0
	// SigningKey specifies the purpose of key to be used in signing/verification operations
	SigningKey KeyPurpose = 1
	// EncryptionKey specifies the purpose of key to be used in encryption/decryption operations
	EncryptionKey KeyPurpose = 2
)

// KeyRequestGen contains the algorithm and key size for a new private key.
type KeyRequestGen interface {
	Algo() string
	Label() string
	Size() int
	Generate() (crypto.PrivateKey, error)
	SigAlgo() x509.SignatureAlgorithm
	Purpose() int
}

// KeyRequest contains the algorithm and key size for a new private key:
// A is AlgoRSA, AlgoECDSA or AlgoMLDSA (case-insensitive) and S the key
// size in bits, the curve size or the ML-DSA parameter set number.
type KeyRequest struct {
	L string     `json:"label" yaml:"label"`
	A string     `json:"algo"  yaml:"algo"`
	S int        `json:"size"  yaml:"size"`
	P KeyPurpose `json:"purpose"  yaml:"purpose"`

	prov cryptoprov.Provider `json:"-"  yaml:"-"`
}

// Label returns the requested key label.
func (kr *KeyRequest) Label() string {
	return kr.L
}

// Algo returns the requested key algorithm represented as a string.
func (kr *KeyRequest) Algo() string {
	return kr.A
}

// Size returns the requested key size.
func (kr *KeyRequest) Size() int {
	return kr.S
}

// Purpose returns the purpose of the key .
func (kr *KeyRequest) Purpose() int {
	return int(kr.P)
}

// SigAlgo returns an appropriate X.509 signature algorithm given the
// key request's type and size.
func (kr *KeyRequest) SigAlgo() x509.SignatureAlgorithm {
	return SigAlgo(kr.Algo(), kr.Size())
}

// Generate generates a key as specified in the request: RSA, ECDSA or
// ML-DSA (through cryptoprov.KeyGenerator.GenerateMLDSAKey; a provider
// whose backend lacks ML-DSA returns its own error). ML-DSA is a signature
// scheme, so an EncryptionKey purpose is rejected for it.
func (kr *KeyRequest) Generate() (crypto.PrivateKey, error) {
	switch algo := kr.Algo(); normalizeAlgo(algo) {
	case AlgoRSA:
		err := validateRSAKeyPairInfoHandler(kr.Size())
		if err != nil {
			return nil, errors.WithMessage(err, "validate RSA key")
		}
		pk, err := kr.prov.GenerateRSAKey(kr.Label(), kr.Size(), kr.Purpose())
		if err != nil {
			return nil, errors.WithMessage(err, "generate RSA key")
		}
		return pk, nil
	case AlgoECDSA:
		err := validateECDSAKeyPairCurveInfoHandler(kr.Size())
		if err != nil {
			return nil, errors.WithMessage(err, "validate ECDSA key")
		}

		var curve elliptic.Curve
		switch kr.Size() {
		case CurveP256:
			curve = elliptic.P256()
		case CurveP384:
			curve = elliptic.P384()
		case CurveP521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("invalid curve")
		}
		pk, err := kr.prov.GenerateECDSAKey(kr.Label(), curve)
		if err != nil {
			return nil, errors.WithMessage(err, "generate ECDSA key")
		}
		return pk, nil
	case AlgoMLDSA:
		if kr.Purpose() == int(EncryptionKey) {
			return nil, errors.Errorf("validate ML-DSA key: unsupported key purpose: %d, ML-DSA keys are signing keys", kr.Purpose())
		}
		params, err := cryptoprov.MLDSAParameters(kr.Size())
		if err != nil {
			return nil, errors.WithMessage(err, "validate ML-DSA key")
		}
		pk, err := kr.prov.GenerateMLDSAKey(kr.Label(), params)
		if err != nil {
			return nil, errors.WithMessage(err, "generate ML-DSA key")
		}
		return pk, nil
	default:
		return nil, errors.Errorf("invalid algorithm: %s", algo)
	}
}

// normalizeAlgo returns the canonical, upper-case algorithm name of algo,
// folding the "MLDSA" spelling into AlgoMLDSA.
func normalizeAlgo(algo string) string {
	upper := strings.ToUpper(strings.TrimSpace(algo))
	if upper == algoMLDSAAlias {
		return AlgoMLDSA
	}
	return upper
}

// IsPostQuantumAlgo reports whether algo names a post-quantum key
// algorithm a KeyRequest can ask for: ML-DSA (case-insensitive, with or
// without the hyphen).
func IsPostQuantumAlgo(algo string) bool {
	return normalizeAlgo(algo) == AlgoMLDSA
}

// NewKeyRequest returns KeyRequest from given parameters
func (c *Provider) NewKeyRequest(label, algo string, keySize int, purpose KeyPurpose) *KeyRequest {
	return &KeyRequest{
		L:    label,
		A:    algo,
		S:    keySize,
		P:    purpose,
		prov: c.provider,
	}
}

// NewKeyRequest returns KeyRequest from given parameters
func NewKeyRequest(prov cryptoprov.Provider, label, algo string, keySize int, purpose KeyPurpose) *KeyRequest {
	return &KeyRequest{
		L:    label,
		A:    algo,
		S:    keySize,
		P:    purpose,
		prov: prov,
	}
}

// validateRSAKeyPairInfoHandler validates size of the RSA key
func validateRSAKeyPairInfoHandler(size int) error {
	if size < 2048 {
		return errors.Errorf("RSA key is too weak: %d", size)
	}
	if size > 4096 {
		return errors.Errorf("RSA key size too large: %d", size)
	}

	return nil
}

// validateECDSAKeyPairCurveInfoHandler validates size of the ECDSA key
func validateECDSAKeyPairCurveInfoHandler(size int) error {
	switch size {
	case CurveP256, CurveP384, CurveP521:
		return nil
	}
	return errors.Errorf("invalid curve size: %d", size)
}

// SigAlgo returns the signature algorithm for a key of algo ("RSA",
// "ECDSA" or "ML-DSA", case-insensitive) and size, as DefaultSigAlgo
// chooses it from a key: RSA 2048 and 3072 bits SHA-256 (XPKI-114), 4096
// bits and above SHA-512; ECDSA by curve size; ML-DSA by parameter set
// (x509.MLDSA44, MLDSA65 or MLDSA87). Other algorithms, and an ML-DSA
// size that is not a parameter set, give x509.UnknownSignatureAlgorithm.
func SigAlgo(algo string, size int) x509.SignatureAlgorithm {
	switch normalizeAlgo(algo) {
	case AlgoRSA:
		switch {
		case size >= 4096:
			return x509.SHA512WithRSA
		case size >= 2048:
			return x509.SHA256WithRSA
		default:
			// SHA-1 signatures are rejected by x509.CreateCertificate;
			// SHA-256 is the floor for any key size.
			return x509.SHA256WithRSA
		}
	case AlgoECDSA:
		switch size {
		case CurveP521:
			return x509.ECDSAWithSHA512
		case CurveP384:
			return x509.ECDSAWithSHA384
		case CurveP256:
			return x509.ECDSAWithSHA256
		default:
			return x509.ECDSAWithSHA256
		}
	case AlgoMLDSA:
		params, err := cryptoprov.MLDSAParameters(size)
		if err != nil {
			return x509.UnknownSignatureAlgorithm
		}
		return mldsaSigAlgo(params)
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// mldsaSigAlgo returns the X.509 signature algorithm of an ML-DSA key of
// params, which is fixed by the parameter set.
func mldsaSigAlgo(params mldsa.Parameters) x509.SignatureAlgorithm {
	switch params {
	case mldsa.MLDSA44():
		return x509.MLDSA44
	case mldsa.MLDSA65():
		return x509.MLDSA65
	case mldsa.MLDSA87():
		return x509.MLDSA87
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
