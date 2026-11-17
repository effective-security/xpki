package cryptoprov

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha3"
	"reflect"

	"github.com/cockroachdb/errors"
)

const (
	// MLDSA44, MLDSA65 and MLDSA87 are the FIPS 204 parameter set numbers as
	// csr.KeyRequest.Size and certutil.KeyInfo.KeySize carry them.
	MLDSA44 = 44
	MLDSA65 = 65
	MLDSA87 = 87

	// MetaParameterSet is the KeyInfo.Meta key under which a provider
	// reports the parameter set of an ML-DSA key, for example "ML-DSA-65".
	MetaParameterSet = "parameter_set"

	// MLDSAMuSize is the length in bytes of the ML-DSA message
	// representative μ (FIPS 204, Algorithm 7) that a signer accepts with
	// crypto.MLDSAMu.
	MLDSAMuSize = 64

	// mldsaMaxContextSize is the longest context string FIPS 204 allows.
	mldsaMaxContextSize = 255

	// mldsaTrSize is the length of tr, the hash of the public key that μ
	// binds the message to.
	mldsaTrSize = 64

	// mldsaDomainPure is the domain separator of a pure (not pre-hashed)
	// ML-DSA signature in M'.
	mldsaDomainPure = 0
)

// MLDSAParameters returns the ML-DSA parameter set for its FIPS 204 number:
// MLDSA44, MLDSA65 or MLDSA87. Any other number is an error.
func MLDSAParameters(size int) (mldsa.Parameters, error) {
	switch size {
	case MLDSA44:
		return mldsa.MLDSA44(), nil
	case MLDSA65:
		return mldsa.MLDSA65(), nil
	case MLDSA87:
		return mldsa.MLDSA87(), nil
	}
	return mldsa.Parameters{}, errors.Errorf("invalid ML-DSA parameter set (expected %d, %d or %d): %d", MLDSA44, MLDSA65, MLDSA87, size)
}

// MLDSASize returns the FIPS 204 number of an ML-DSA parameter set, MLDSA44,
// MLDSA65 or MLDSA87, as GenerateKeyRequest.Size and KeyInfo.Size carry it,
// and 0 for any other value. It is the inverse of MLDSAParameters.
func MLDSASize(params mldsa.Parameters) int {
	switch params {
	case mldsa.MLDSA44():
		return MLDSA44
	case mldsa.MLDSA65():
		return MLDSA65
	case mldsa.MLDSA87():
		return MLDSA87
	default:
		return 0
	}
}

// MLDSASignerOptions validates opts against the contract every ML-DSA
// signer of this module follows: ML-DSA signs a message, not a digest. The
// signer accepts the message with nil options, options whose HashFunc is
// zero (x509.CreateCertificate passes crypto.Hash(0)) or *mldsa.Options
// carrying an optional context string (a nil *mldsa.Options counts as
// nil), and a 64-byte message representative μ with crypto.MLDSAMu. Any
// other hash, and a nil pointer of any other options type, is an error, so
// a hash-then-sign caller fails instead of signing a digest as if it were
// the message. It returns whether the message is a μ and the context.
func MLDSASignerOptions(opts crypto.SignerOpts) (mu bool, context string, err error) {
	if opts == nil {
		return false, "", nil
	}
	if o, ok := opts.(*mldsa.Options); ok {
		if o == nil {
			return false, "", nil
		}
		if len(o.Context) > mldsaMaxContextSize {
			return false, "", errors.Errorf("ML-DSA context is too long: %d bytes (at most %d)", len(o.Context), mldsaMaxContextSize)
		}
		return false, o.Context, nil
	}
	if isNilSignerOpts(opts) {
		// a nil *rsa.PSSOptions or alike: a caller bug whose HashFunc would panic
		return false, "", errors.Errorf("ML-DSA signs a message, not a digest: unsupported signer options %T", opts)
	}
	switch h := opts.HashFunc(); h {
	case 0:
		return false, "", nil
	case crypto.MLDSAMu:
		return true, "", nil
	default:
		return false, "", errors.Errorf("ML-DSA signs a message, not a digest: unsupported signer options %s", h)
	}
}

// MLDSAMu returns μ, the message representative an ML-DSA signature is
// computed over (FIPS 204, Algorithm 7): SHAKE256(tr ‖ 0x00 ‖ len(context)
// ‖ context ‖ message, 64) with tr = SHAKE256(pk, 64). A KMS or HSM
// external-μ operation over it produces the same signature as signing
// message with context locally, which mldsa.Verify checks with the same
// message and context. The context is at most 255 bytes.
func MLDSAMu(pub *mldsa.PublicKey, context string, message []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("ML-DSA public key is required")
	}
	if len(context) > mldsaMaxContextSize {
		return nil, errors.Errorf("ML-DSA context is too long: %d bytes (at most %d)", len(context), mldsaMaxContextSize)
	}
	tr := sha3.SumSHAKE256(pub.Bytes(), mldsaTrSize)
	h := sha3.NewSHAKE256()
	_, _ = h.Write(tr)
	_, _ = h.Write([]byte{mldsaDomainPure, byte(len(context))})
	_, _ = h.Write([]byte(context))
	_, _ = h.Write(message)
	mu := make([]byte, MLDSAMuSize)
	_, _ = h.Read(mu)
	return mu, nil
}

// isNilSignerOpts reports whether opts is a nil pointer, whose HashFunc may
// dereference it.
func isNilSignerOpts(opts crypto.SignerOpts) bool {
	v := reflect.ValueOf(opts)
	return v.Kind() == reflect.Pointer && v.IsNil()
}
