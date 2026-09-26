package gcpkmscrypto

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"hash/crc32"
	"io"
	"reflect"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/metricskey"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// signScheme is what a KMS signing algorithm fixes: the digest hash and
// whether the RSA padding is PSS.
type signScheme struct {
	hash crypto.Hash
	pss  bool
}

// signSchemes maps the KMS algorithms that sign a digest to their scheme.
// KMS rejects a digest of another hash, and the padding cannot be chosen
// per call, so Sign checks its options against the scheme (XPKI-019). Raw
// PKCS#1, Ed25519, post-quantum, decryption and MAC algorithms are not
// supported, and neither is secp256k1, whose public key crypto/x509 cannot
// parse (XPKI-119).
var signSchemes = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]signScheme{
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:   {hash: crypto.SHA256, pss: true},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:   {hash: crypto.SHA256, pss: true},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:   {hash: crypto.SHA256, pss: true},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:   {hash: crypto.SHA512, pss: true},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256: {hash: crypto.SHA256},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256: {hash: crypto.SHA256},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256: {hash: crypto.SHA256},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512: {hash: crypto.SHA512},
	kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:        {hash: crypto.SHA256},
	kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:        {hash: crypto.SHA384},
}

// Signer implements crypto.Signer interface
type Signer struct {
	keyID     string
	label     string
	pubKey    crypto.PublicKey
	algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	prov      *Provider
	// name is the resource name of the version Sign uses, resolved once by
	// NewSigner; nameErr is why keyID could not be resolved.
	name    string
	nameErr error
}

// NewSigner creates a signer for the key version keyID, "K/cryptoKeyVersions/N",
// whose KMS algorithm is algorithm; Sign accepts only options that match it.
// A keyID that names no version makes every Sign fail.
func NewSigner(keyID string, label string, publicKey crypto.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, prov *Provider) crypto.Signer {
	logger.KV(xlog.DEBUG, "id", keyID, "label", label, "algorithm", algorithm.String())
	s := &Signer{
		keyID:     keyID,
		label:     label,
		pubKey:    publicKey,
		algorithm: algorithm,
		prov:      prov,
	}
	key, version, err := keyIDVersion(keyID)
	switch {
	case err != nil:
		s.nameErr = err
	case version == "":
		s.nameErr = errors.Errorf("signer key ID names no version: %s", keyID)
	case prov != nil:
		s.name = versionName(prov.keyName(key), version)
	}
	return s
}

// KeyID returns the key ID of the signer, which names its version.
func (s *Signer) KeyID() string {
	return s.keyID
}

// Label returns key label of the signer
func (s *Signer) Label() string {
	return s.label
}

// Algorithm returns the KMS algorithm of the signer's key version.
func (s *Signer) Algorithm() kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm {
	return s.algorithm
}

// Public returns public key for the signer
func (s *Signer) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *Signer) String() string {
	return fmt.Sprintf("id=%s, label=%s",
		s.KeyID(),
		s.Label(),
	)
}

// Sign signs digest with the KMS key version. opts is required: its hash
// must be the key algorithm's, digest must have that hash's length, and
// *rsa.PSSOptions with the hash-length salt (rsa.PSSSaltLengthEqualsHash or
// the explicit size; KMS cannot honour PSSSaltLengthAuto, XPKI-124) are
// required for PSS algorithms and rejected for others (XPKI-019,
// XPKI-025). Invalid options fail before any RPC. The response is accepted
// only when KMS verified the digest checksum and the signature matches its
// checksum (XPKI-023). After the provider is closed, Sign returns ErrClosed.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "sign")

	if s.prov == nil {
		return nil, errors.New("signer has no provider")
	}
	if s.nameErr != nil {
		return nil, s.nameErr
	}
	kmsDigest, err := signDigest(digest, opts, s.algorithm)
	if err != nil {
		return nil, err
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:         s.name,
		Digest:       kmsDigest,
		DigestCrc32C: wrapperspb.Int64(int64(Crc32c(digest))),
	}

	if err = s.prov.enter(); err != nil {
		return nil, err
	}
	defer s.prov.exit()

	result, err := s.prov.AsymmetricSign(context.Background(), req)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to sign")
	}
	if result == nil {
		return nil, errors.WithMessage(errEmptyResponse, "unable to sign")
	}

	// Integrity verification of the result; see
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if !result.GetVerifiedDigestCrc32C() {
		return nil, errors.Errorf("request corrupted in-transit")
	}
	// a missing checksum is never taken as a verified signature
	sigCRC := result.GetSignatureCrc32C()
	if sigCRC == nil {
		return nil, errors.Errorf("response has no signature checksum")
	}
	if int64(Crc32c(result.GetSignature())) != sigCRC.GetValue() {
		return nil, errors.Errorf("response corrupted in-transit")
	}

	return result.GetSignature(), nil
}

// signDigest validates opts and digest against the key algorithm and
// returns the KMS digest.
func signDigest(digest []byte, opts crypto.SignerOpts, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (*kmspb.Digest, error) {
	scheme, ok := signSchemes[algorithm]
	if !ok {
		return nil, errors.Errorf("unsupported key algorithm: %s", algorithm)
	}
	if isNilOpts(opts) {
		return nil, errors.New("signer options are required")
	}
	hash := opts.HashFunc()
	if hash != scheme.hash {
		return nil, errors.Errorf("hash %s does not match key algorithm %s", hash, algorithm)
	}
	if len(digest) != hash.Size() {
		return nil, errors.Errorf("digest length %d does not match %s (%d bytes)", len(digest), hash, hash.Size())
	}
	pssOpts, pss := opts.(*rsa.PSSOptions)
	switch {
	case pss && !scheme.pss:
		return nil, errors.Errorf("key algorithm %s does not use PSS padding", algorithm)
	case !pss && scheme.pss:
		return nil, errors.Errorf("key algorithm %s requires *rsa.PSSOptions", algorithm)
	case pss && !pssSaltLengthOK(pssOpts.SaltLength, hash):
		return nil, errors.Errorf("PSS salt length %d is not supported: KMS uses the digest length %d", pssOpts.SaltLength, hash.Size())
	}

	switch hash {
	case crypto.SHA256:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}, nil
	case crypto.SHA384:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}, nil
	case crypto.SHA512:
		return &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}, nil
	default:
		return nil, errors.Errorf("unsupported hash: %s", hash)
	}
}

// pssSaltLengthOK reports whether saltLength asks for what KMS uses, the
// digest length. rsa.PSSSaltLengthAuto asks for the largest possible salt
// when signing, which KMS cannot produce, so it is rejected (XPKI-124).
func pssSaltLengthOK(saltLength int, hash crypto.Hash) bool {
	return saltLength == rsa.PSSSaltLengthEqualsHash || saltLength == hash.Size()
}

// isNilOpts reports whether opts is nil or a nil pointer, such as a nil
// *rsa.PSSOptions, whose HashFunc would panic.
func isNilOpts(opts crypto.SignerOpts) bool {
	if opts == nil {
		return true
	}
	v := reflect.ValueOf(opts)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// Crc32c computes digest's CRC32C.
func Crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
