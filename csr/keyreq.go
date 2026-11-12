package csr

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/cryptoprov"
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
	Generate(ctx context.Context) (crypto.PrivateKey, error)
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

// Validate reports whether the request names a known algorithm with a size
// and purpose it supports, without generating a key, so a configuration can
// be rejected before the first use. Generate calls it. ML-DSA is a signature
// scheme, so an EncryptionKey purpose is rejected for it.
func (kr *KeyRequest) Validate() error {
	switch algo := kr.Algo(); normalizeAlgo(algo) {
	case AlgoRSA:
		if err := validateRSAKeyPairInfoHandler(kr.Size()); err != nil {
			return errors.WithMessage(err, "validate RSA key")
		}
	case AlgoECDSA:
		if err := validateECDSAKeyPairCurveInfoHandler(kr.Size()); err != nil {
			return errors.WithMessage(err, "validate ECDSA key")
		}
	case AlgoMLDSA:
		if kr.Purpose() == int(EncryptionKey) {
			return errors.Errorf("validate ML-DSA key: unsupported key purpose: %d, ML-DSA keys are signing keys", kr.Purpose())
		}
		if _, err := cryptoprov.MLDSAParameters(kr.Size()); err != nil {
			return errors.WithMessage(err, "validate ML-DSA key")
		}
	default:
		return errors.Errorf("invalid algorithm: %s", algo)
	}
	return nil
}

// Generate generates a key as specified in the request (see Validate)
// through cryptoprov.KeyGenerator.GenerateKey of its provider, with ctx. The
// purpose selects the usage of an RSA key (Undefined is a signing key); an
// ECDSA or ML-DSA key is always a signing key. A provider whose backend
// lacks the algorithm, the size or the usage returns an error that wraps
// cryptoprov.ErrNotSupported.
func (kr *KeyRequest) Generate(ctx context.Context) (crypto.PrivateKey, error) {
	if err := kr.Validate(); err != nil {
		return nil, err
	}
	// the algorithm names are the cryptoprov key types
	algo := normalizeAlgo(kr.Algo())
	usage := cryptoprov.KeyUsageSign
	if algo == AlgoRSA {
		usage = cryptoprov.KeyUsage(kr.Purpose())
	}
	pk, err := kr.prov.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
		Label: kr.Label(),
		Type:  algo,
		Size:  kr.Size(),
		Usage: usage,
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "generate %s key", algo)
	}
	return pk, nil
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
