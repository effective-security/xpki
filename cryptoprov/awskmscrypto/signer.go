package awskmscrypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/metricskey"
)

// Signer implements crypto.Signer interface
type Signer struct {
	keyID string
	label string
	//signAlgo x509.SignatureAlgorithm
	signingAlgorithms []types.SigningAlgorithmSpec
	pubKey            crypto.PublicKey
	kmsClient         KmsClient
}

// NewSigner creates new signer
func NewSigner(keyID string, label string, signingAlgorithms []types.SigningAlgorithmSpec, publicKey crypto.PublicKey, kmsClient KmsClient) crypto.Signer {
	logger.KV(xlog.DEBUG, "id", keyID, "label", label, "algos", signingAlgorithms)
	return &Signer{
		keyID:             keyID,
		label:             label,
		signingAlgorithms: signingAlgorithms,
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

// Sign implements signing operation
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "sign")

	sigAlgo, err := sigAlgo(s.pubKey, opts)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to determine signature algorithm")
	}

	req := &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpec(sigAlgo),
	}
	resp, err := s.kmsClient.Sign(context.Background(), req)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to sign")
	}
	return resp.Signature, nil
}

func sigAlgo(publicKey crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	var pubalgo string
	var pad string

	switch publicKey.(type) {
	case *rsa.PublicKey:
		pubalgo = "RSASSA_"

		switch t := opts.(type) {
		case *rsa.PSSOptions:
			pad = "PSS_"
			opts = t.Hash
		default:
			pad = "PKCS1_V1_5_"
		}
	case *ecdsa.PublicKey:
		pubalgo = "ECDSA_"
	default:
		return "", errors.Errorf("unknown type of public key: %s", reflect.TypeOf(publicKey))
	}

	var algo string
	switch opts.HashFunc() {
	case crypto.SHA256:
		algo = pubalgo + pad + "SHA_256"
	case crypto.SHA384:
		algo = pubalgo + pad + "SHA_384"
	case crypto.SHA512:
		algo = pubalgo + pad + "SHA_512"
	default:
		return "", errors.Errorf("unsupported hash: %s", reflect.TypeOf(opts))

	}
	return algo, nil
}
