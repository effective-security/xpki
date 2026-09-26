package gcpkmscrypto

import (
	"context"
	"crypto"
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

// Signer implements crypto.Signer interface
type Signer struct {
	keyID  string
	label  string
	pubKey crypto.PublicKey
	prov   *Provider
}

// NewSigner creates new signer
func NewSigner(keyID string, label string, publicKey crypto.PublicKey, prov *Provider) crypto.Signer {
	logger.KV(xlog.DEBUG, "id", keyID, "label", label)
	return &Signer{
		keyID:  keyID,
		label:  label,
		pubKey: publicKey,
		prov:   prov,
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

// Sign signs digest with the KMS key. opts is required and must name
// SHA-256, SHA-384 or SHA-512, and digest must have that hash's length; the
// padding and curve come from the key's KMS algorithm. Invalid options fail
// before any RPC (XPKI-025). The response is accepted only when KMS
// verified the digest checksum and the signature matches its checksum
// (XPKI-023). After the provider is closed, Sign returns ErrClosed.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "sign")

	if s.prov == nil {
		return nil, errors.New("signer has no provider")
	}
	kmsDigest, err := signDigest(digest, opts)
	if err != nil {
		return nil, err
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:         s.prov.keyVersionName(s.KeyID()),
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
	// if result.Name != req.Name {
	//      return errors.New("AsymmetricSign: request corrupted in-transit")
	// }
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

// signDigest validates opts and digest and returns the KMS digest.
func signDigest(digest []byte, opts crypto.SignerOpts) (*kmspb.Digest, error) {
	if isNilOpts(opts) {
		return nil, errors.New("signer options are required")
	}
	hash := opts.HashFunc()
	var kmsDigest *kmspb.Digest
	switch hash {
	case crypto.SHA256:
		kmsDigest = &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}
	case crypto.SHA384:
		kmsDigest = &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}
	case crypto.SHA512:
		kmsDigest = &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: digest}}
	default:
		return nil, errors.Errorf("unsupported hash: %s", hash)
	}
	if len(digest) != hash.Size() {
		return nil, errors.Errorf("digest length %d does not match %s (%d bytes)", len(digest), hash, hash.Size())
	}
	return kmsDigest, nil
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
