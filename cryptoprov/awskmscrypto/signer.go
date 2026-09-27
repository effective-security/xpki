package awskmscrypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/metricskey"
)

// signScheme is what selects a KMS signing algorithm: the key type, the RSA
// padding and the digest hash.
type signScheme struct {
	rsa  bool
	pss  bool
	hash crypto.Hash
}

// signingAlgorithms maps a scheme to the KMS algorithm that signs a digest
// with it. SM2, ML-DSA and Ed25519 keys are not supported: crypto/x509 can
// not parse an SM2 or ML-DSA public key, and Ed25519 signs a message, not a
// digest.
var signingAlgorithms = map[signScheme]types.SigningAlgorithmSpec{
	{rsa: true, pss: true, hash: crypto.SHA256}: types.SigningAlgorithmSpecRsassaPssSha256,
	{rsa: true, pss: true, hash: crypto.SHA384}: types.SigningAlgorithmSpecRsassaPssSha384,
	{rsa: true, pss: true, hash: crypto.SHA512}: types.SigningAlgorithmSpecRsassaPssSha512,
	{rsa: true, hash: crypto.SHA256}:            types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	{rsa: true, hash: crypto.SHA384}:            types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
	{rsa: true, hash: crypto.SHA512}:            types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	{hash: crypto.SHA256}:                       types.SigningAlgorithmSpecEcdsaSha256,
	{hash: crypto.SHA384}:                       types.SigningAlgorithmSpecEcdsaSha384,
	{hash: crypto.SHA512}:                       types.SigningAlgorithmSpecEcdsaSha512,
}

// Signer implements crypto.Signer interface
type Signer struct {
	keyID             string
	label             string
	signingAlgorithms []types.SigningAlgorithmSpec
	pubKey            crypto.PublicKey
	kmsClient         KmsClient
}

// NewSigner creates a signer for the KMS key keyID. signingAlgorithms are
// the algorithms KMS reports for the key (KeyMetadata.SigningAlgorithms or
// GetPublicKeyOutput.SigningAlgorithms); Sign accepts only those, so a key
// without any, such as an ENCRYPT_DECRYPT key, can not sign.
func NewSigner(keyID string, label string, signingAlgorithms []types.SigningAlgorithmSpec, publicKey crypto.PublicKey, kmsClient KmsClient) crypto.Signer {
	logger.KV(xlog.DEBUG, "id", keyID, "label", label, "algos", signingAlgorithms)
	return &Signer{
		keyID:             keyID,
		label:             label,
		signingAlgorithms: slices.Clone(signingAlgorithms),
		pubKey:            publicKey,
		kmsClient:         kmsClient,
	}
}

// KeyID returns key id of the signer
func (s *Signer) KeyID() string {
	return s.keyID
}

// Label returns key label of the signer
func (s *Signer) Label() string {
	return s.label
}

// SigningAlgorithms returns the KMS signing algorithms the key supports.
func (s *Signer) SigningAlgorithms() []types.SigningAlgorithmSpec {
	return slices.Clone(s.signingAlgorithms)
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

// Sign signs digest with the KMS key. opts is required (XPKI-025): its hash
// selects the KMS algorithm and digest must have that hash's length.
// *rsa.PSSOptions select RSASSA_PSS for an RSA key and are rejected for an
// ECDSA key; the salt must be rsa.PSSSaltLengthEqualsHash or the hash size,
// the only salt KMS produces (rsa.PSSSaltLengthAuto asks for a maximal salt
// and is rejected). The algorithm must be one the key supports, as KMS
// reported when the signer was created; for an ECDSA key that is the
// algorithm of its curve. Invalid options fail before any RPC.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "sign")

	algorithm, err := s.signingAlgorithm(digest, opts)
	if err != nil {
		return nil, err
	}

	req := &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: algorithm,
	}
	resp, err := s.kmsClient.Sign(context.Background(), req)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to sign")
	}
	if resp == nil || len(resp.Signature) == 0 {
		return nil, errors.Wrap(errEmptyResponse, "unable to sign")
	}
	return resp.Signature, nil
}

// signingAlgorithm validates digest and opts against the key and returns
// the KMS algorithm to sign with.
func (s *Signer) signingAlgorithm(digest []byte, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	if isNilOpts(opts) {
		return "", errors.New("signer options are required")
	}
	pssOpts, pss := opts.(*rsa.PSSOptions)
	scheme := signScheme{
		hash: opts.HashFunc(),
	}
	switch s.pubKey.(type) {
	case *rsa.PublicKey:
		scheme.rsa = true
		scheme.pss = pss
	case *ecdsa.PublicKey:
		if pss {
			return "", errors.New("PSS options are not valid for an ECDSA key")
		}
	default:
		return "", errors.Errorf("unsupported public key type: %T", s.pubKey)
	}

	algorithm, ok := signingAlgorithms[scheme]
	if !ok {
		return "", errors.Errorf("unsupported hash: %s", scheme.hash)
	}
	if !slices.Contains(s.signingAlgorithms, algorithm) {
		return "", errors.Errorf("key %s does not support %s (supported: %v)", s.keyID, algorithm, s.signingAlgorithms)
	}
	if size := scheme.hash.Size(); len(digest) != size {
		return "", errors.Errorf("digest length %d does not match %s (%d bytes)", len(digest), scheme.hash, size)
	}
	if pss && !pssSaltLengthOK(pssOpts.SaltLength, scheme.hash) {
		return "", errors.Errorf("PSS salt length %d is not supported: KMS uses the digest length %d", pssOpts.SaltLength, scheme.hash.Size())
	}
	return algorithm, nil
}

// pssSaltLengthOK reports whether saltLength asks for what KMS uses, the
// digest length. rsa.PSSSaltLengthAuto asks for the largest possible salt
// when signing, which KMS does not produce, so it is rejected.
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
