package gcpkmscrypto

import (
	"cmp"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/metricskey"
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki/cryptoprov", "gcpkms")

// ProviderName specifies a provider name
const ProviderName = "GCPKMS"

const (
	// attribute names in TokenConfig.Attributes
	attrEndpoint = "Endpoint"
	attrKeyring  = "Keyring"

	// resource name segments
	cryptoKeysSegment = "/cryptoKeys/"
	versionsSegment   = "/cryptoKeyVersions/"
	// firstVersion is the version CreateCryptoKey creates.
	firstVersion = "1"

	// labelKey is the CryptoKey label that holds the key label.
	labelKey = "label"

	// maxKeyIDLength is the KMS limit on a CryptoKey id ([a-zA-Z0-9_-]{1,63})
	// and maxLabelLength the limit on a label value.
	maxKeyIDLength = 63
	maxLabelLength = 63
	// keyIDSuffixLength is the length of the random suffix of a key ID and
	// keyIDSeparator separates it from the label.
	keyIDSuffixLength = 8
	keyIDSeparator    = "-"
	// createAttempts is how many key IDs genKey tries when KMS reports
	// ALREADY_EXISTS.
	createAttempts = 3

	// listConcurrency is how many version listings ListKeys has in flight
	// at once when it needs the state of asymmetric keys.
	listConcurrency = 8

	// filterAnd joins the conditions of a ListCryptoKeys filter, and
	// filterLabels is the field its label conditions name.
	filterAnd    = " AND "
	filterLabels = "labels."

	// readyPollInterval and readyPollAttempts bound the wait for a new key
	// version to leave PENDING_GENERATION (XPKI-024).
	readyPollInterval = time.Second
	readyPollAttempts = 60

	// reasonAlgorithmNotSupported is the ErrorInfo reason of the KMS error
	// for an algorithm that the requested protection level does not offer.
	reasonAlgorithmNotSupported = "ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL"

	// discardTimeout bounds the destruction of a key whose creation did not
	// complete, which runs even when the context of the creation is done.
	discardTimeout = 30 * time.Second

	// Algorithm name prefixes of the RSA families, for KeyInfo.Type, and
	// what separates the parts of an algorithm name.
	rsaSignAlgorithmPrefix    = "RSA_SIGN_"
	rsaDecryptAlgorithmPrefix = "RSA_DECRYPT_"
	algorithmNameSeparator    = "_"
	// minRSAKeySize is the smallest number in an RSA algorithm name that is
	// a key size and not part of a hash name.
	minRSAKeySize = 1024

	// Names of the KeyInfo.Meta entries.
	metaPurpose    = "purpose"
	metaProtection = "protection"
	metaState      = "state"
	metaAlgo       = "algo"

	// Metric actions of GenerateKey by key type.
	actionGenRSA   = "genkey_rsa"
	actionGenECDSA = "genkey_ecdsa"
	actionGenMLDSA = "genkey_mldsa"

	// uriSerial is the serial attribute of exported URIs: the URI parser
	// requires one, and the version is carried by the id (XPKI-020).
	uriSerial = "1"
)

func init() {
	_ = cryptoprov.Register(ProviderName, KmsLoader)
}

// KmsClient is the subset of the KMS client the provider uses.
type KmsClient interface {
	ListCryptoKeys(context.Context, *kmspb.ListCryptoKeysRequest, ...gax.CallOption) *kms.CryptoKeyIterator
	ListCryptoKeyVersions(context.Context, *kmspb.ListCryptoKeyVersionsRequest, ...gax.CallOption) *kms.CryptoKeyVersionIterator
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	Close() error
}

// KmsClientFactory creates the KMS client for Init. endpoint is the Endpoint
// attribute of the token config, empty for the default endpoint (XPKI-021).
// The default factory uses Application Default Credentials. Tests override
// the variable.
var KmsClientFactory = func(endpoint string) (KmsClient, error) {
	return newKmsClient(context.Background(), endpoint)
}

// newKmsClient creates the SDK client, at endpoint when it is not empty,
// with opts added to the SDK defaults.
func newKmsClient(ctx context.Context, endpoint string, opts ...option.ClientOption) (KmsClient, error) {
	if endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create kms client")
	}

	return client, nil
}

// ErrClosed is returned after Close by the operations that call KMS:
// GenerateKey, GetKey, ListKeys, KeyInfo, DestroyKey and Signer.Sign.
// Operations that do not call KMS, ExportKey and IdentifyKey, keep working.
var ErrClosed = errors.New("gcpkms: provider is closed")

// errEmptyResponse is returned when KMS returns neither a response nor an
// error.
var errEmptyResponse = errors.New("empty response")

// Provider implements Provider interface for KMS.
//
// A key ID is a CryptoKey id, "K", or one of its versions,
// "K/cryptoKeyVersions/N" (XPKI-020). GetKey, KeyInfo and DestroyKey use the
// named version. A bare id is resolved at each call: GetKey signs with the
// newest ENABLED version (none is an error), KeyInfo describes the newest
// ENABLED version, else the newest one not DESTROYED, else the key alone
// (XPKI-117), and DestroyKey schedules every ENABLED or DISABLED version for
// destruction (XPKI-116).
// Generated and loaded signers identify themselves by their version, so the
// URI from ExportKey pins it; ExportKey itself makes no RPC and does not
// resolve a bare id.
//
// Its methods and signers are safe for concurrent use with Close: Close
// rejects new operations with ErrClosed, waits for those in flight, then
// closes the client. A wait for key generation ends as soon as Close is
// called. The embedded KmsClient is set up by Init; its methods called
// directly bypass that guard.
type Provider struct {
	KmsClient

	tc       cryptoprov.TokenConfig
	endpoint string
	keyring  string

	// wait for key generation (XPKI-024); zero values mean the defaults
	pollInterval time.Duration
	pollAttempts int
	// sleep replaces the wait between polls in tests
	sleep func(context.Context, time.Duration) error

	mu        sync.Mutex
	active    int
	closed    bool
	drained   chan struct{}
	closeOnce sync.Once
	// closing is closed by Close to end a wait for key generation
	closing chan struct{}
}

// Init configures the KMS provider from the token config. The Keyring
// attribute is required (XPKI-120); Endpoint is optional.
func Init(tc cryptoprov.TokenConfig) (*Provider, error) {
	kmsAttributes := parseKmsAttributes(tc.Attributes())
	endpoint := kmsAttributes[attrEndpoint]
	keyring := kmsAttributes[attrKeyring]
	if keyring == "" {
		return nil, errors.Errorf("gcpkms: the %s attribute is required", attrKeyring)
	}

	client, err := KmsClientFactory(endpoint)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create KMS client")
	}

	return newProvider(tc, client, endpoint, keyring), nil
}

func newProvider(tc cryptoprov.TokenConfig, client KmsClient, endpoint, keyring string) *Provider {
	return &Provider{
		KmsClient:    client,
		tc:           tc,
		endpoint:     endpoint,
		keyring:      keyring,
		pollInterval: readyPollInterval,
		pollAttempts: readyPollAttempts,
		closing:      make(chan struct{}),
	}
}

func parseKmsAttributes(attributes string) map[string]string {
	var kmsAttributes = make(map[string]string)

	for v := range strings.SplitSeq(attributes, ",") {
		name, value, ok := strings.Cut(v, "=")
		if !ok {
			continue
		}
		kmsAttributes[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}

	return kmsAttributes
}

// Manufacturer returns manufacturer for the provider
func (p *Provider) Manufacturer() string {
	return p.tc.Manufacturer()
}

// Model returns model for the provider
func (p *Provider) Model() string {
	return p.tc.Model()
}

// enter registers an operation that uses the client; it returns ErrClosed
// after Close. Each successful enter must be paired with exit. Operations do
// not nest.
func (p *Provider) enter() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.WithStack(ErrClosed)
	}
	p.active++
	return nil
}

// exit ends an operation registered by enter.
func (p *Provider) exit() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
	if p.active == 0 && p.drained != nil {
		close(p.drained)
		p.drained = nil
	}
}

// rsaAlgorithms maps the RSA key sizes GenerateKey creates to their KMS
// algorithm: PKCS#1 v1.5 with SHA-256 for 2048 and 3072 bits and SHA-512 for
// 4096 bits. KMS has no SHA-384 algorithm for 3072-bit keys;
// csr.DefaultSigAlgo follows Signer.SignatureAlgorithm, so CSRs and
// certificates are signed with SHA-256 (XPKI-114).
var rsaAlgorithms = map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
	2048: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
	3072: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
	4096: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
}

// ecAlgorithms maps the ECDSA curve sizes GenerateKey creates to their KMS
// algorithm. KMS has no P-521 signing algorithm.
var ecAlgorithms = map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
	256: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	384: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
}

// mldsaAlgorithms maps the ML-DSA parameter set numbers to the KMS algorithm
// GenerateKey creates: the EXTERNAL_MU variant, so the signer sends the
// locally computed message representative μ instead of the message.
var mldsaAlgorithms = map[int]kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm{
	cryptoprov.MLDSA44: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU,
	cryptoprov.MLDSA65: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU,
	cryptoprov.MLDSA87: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU,
}

// GenerateKey creates an HSM signing key as req describes it and returns
// its signer: RSA of 2048, 3072 or 4096 bits (PKCS#1 v1.5 with SHA-256, or
// SHA-512 for 4096 bits; Sign accepts only that hash), ECDSA on P-256 with
// SHA-256 or P-384 with SHA-384, or ML-DSA-44, 65 or 87 with the
// PQ_SIGN_ML_DSA_*_EXTERNAL_MU algorithm. An ML-DSA signer signs messages,
// computing μ locally (cryptoprov.MLDSASignerOptions); a key created outside
// this provider with the PQ_SIGN_ML_DSA_* algorithm sends the message itself
// and is supported by GetKey too.
//
// req.Label becomes the "label" label and the prefix of the key id
// (KeyLabelAndID), and req.Tags the other labels of the key; "label" is not
// a valid tag name. This provider has no decrypter, so
// cryptoprov.KeyUsageEncrypt is a wrapped cryptoprov.ErrNotSupported before
// any RPC (XPKI-019), as is a size KMS does not offer, such as P-521. An
// algorithm KMS refuses at the HSM protection level is
// cryptoprov.ErrNotSupported too, with the KMS error kept: on 2026-11-12
// that was every ML-DSA algorithm.
func (p *Provider) GenerateKey(ctx context.Context, req *cryptoprov.GenerateKeyRequest) (crypto.PrivateKey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	action := actionGenRSA
	algorithms := rsaAlgorithms
	switch req.Type {
	case certutil.KeyTypeECDSA:
		action = actionGenECDSA
		algorithms = ecAlgorithms
	case certutil.KeyTypeMLDSA:
		action = actionGenMLDSA
		algorithms = mldsaAlgorithms
	}
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, action)

	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	if usage := req.KeyUsage(); usage != cryptoprov.KeyUsageSign {
		return nil, errors.Wrapf(cryptoprov.ErrNotSupported, "unsupported key usage: %s, only signing keys are supported", usage)
	}
	algorithm, ok := algorithms[req.Size]
	if !ok {
		return nil, errors.Wrapf(cryptoprov.ErrNotSupported, "unsupported %s key size: %d", req.Type, req.Size)
	}
	if _, ok := req.Tags[labelKey]; ok {
		return nil, errors.Errorf("invalid tag %q: the name is reserved for the key label", labelKey)
	}

	return p.genKey(ctx, req.Label, algorithm, req.Tags)
}

// genKey creates an HSM signing key with algorithm, named after label by
// KeyLabelAndID and labelled with tags, waits for its first version and
// returns its signer. When
// KMS reports that the key id exists, it tries new ids, createAttempts in
// all (XPKI-022). Close waits for it, but ends its wait for key generation.
// When the key exists but its signer cannot be returned, the key is scheduled
// for destruction, so no billable key is left that the caller has no id for.
func (p *Provider) genKey(ctx context.Context, name string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, tags map[string]string) (crypto.PrivateKey, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	var resp *kmspb.CryptoKey
	var label string
	for attempt := 1; ; attempt++ {
		var keyID string
		label, keyID = KeyLabelAndID(name)
		labels := make(map[string]string, len(tags)+1)
		maps.Copy(labels, tags)
		labels[labelKey] = label
		req := &kmspb.CreateCryptoKeyRequest{
			Parent:      p.keyring,
			CryptoKeyId: keyID,
			CryptoKey: &kmspb.CryptoKey{
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					Algorithm:       algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_HSM,
				},
				Labels: labels,
			},
		}

		var err error
		resp, err = p.CreateCryptoKey(ctx, req)
		if err == nil {
			break
		}
		if status.Code(err) != codes.AlreadyExists || attempt >= createAttempts {
			return nil, createKeyError(err, keyID)
		}
		logger.KV(xlog.WARNING, "reason", "key_id_exists", "keyID", keyID, "attempt", attempt)
	}
	if resp == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to create key")
	}

	logger.KV(xlog.NOTICE,
		"keyID", resp.GetName(),
		"label", label,
	)

	version := versionName(resp.GetName(), firstVersion)
	ver, err := p.waitForVersion(ctx, version)
	if err != nil {
		p.discardVersion(ctx, version)
		return nil, err
	}

	signer, err := p.signerForVersion(ctx, ver, label)
	if err != nil {
		// a version that failed to generate has no key material to destroy
		if isDestroyable(ver.GetState()) {
			p.discardVersion(ctx, version)
		}
		return nil, err
	}
	return signer, nil
}

// createKeyError wraps a CreateCryptoKey failure. KMS refuses an algorithm it
// does not offer at the HSM protection level this provider asks for with
// INVALID_ARGUMENT and the reason reasonAlgorithmNotSupported, as it did for
// the ML-DSA algorithms on 2026-11-12: that error is also
// cryptoprov.ErrNotSupported, and the gRPC status stays reachable.
func createKeyError(err error, keyID string) error {
	wrapped := errors.WithMessagef(err, "failed to create key %s", keyID)
	if apiErr, ok := apierror.FromError(err); ok && apiErr.Reason() == reasonAlgorithmNotSupported {
		return cryptoprov.MarkError(wrapped, cryptoprov.ErrNotSupported)
	}
	return wrapped
}

// discardVersion schedules the destruction of a version whose creation did not
// complete. ctx may be why it did not, so the request has its own deadline. A
// failure is logged with the name for an operator, since the caller gets the
// creation error: KMS refuses a version that is still PENDING_GENERATION.
func (p *Provider) discardVersion(ctx context.Context, name string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discardTimeout)
	defer cancel()
	if err := p.destroyVersion(ctx, name); err != nil {
		logger.KV(xlog.WARNING, "reason", "DestroyCryptoKeyVersion", "name", name, "err", err.Error())
		return
	}
	logger.KV(xlog.WARNING, "reason", "incomplete key scheduled for destruction", "name", name)
}

// waitForVersion polls the version name until its state is no longer
// PENDING_GENERATION and returns it. It polls at most pollAttempts times,
// pollInterval apart, and stops at once on an RPC error, when ctx is done or
// when the provider is closing (XPKI-024). The caller checks the state.
func (p *Provider) waitForVersion(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	attempts := cmp.Or(p.pollAttempts, readyPollAttempts)
	interval := cmp.Or(p.pollInterval, readyPollInterval)

	for attempt := 1; ; attempt++ {
		ver, err := p.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get key version %s", name)
		}
		if ver == nil {
			return nil, errors.WithMessagef(errEmptyResponse, "failed to get key version %s", name)
		}
		state := ver.GetState()
		if state != kmspb.CryptoKeyVersion_PENDING_GENERATION {
			return ver, nil
		}
		if attempt >= attempts {
			return nil, errors.Errorf("key version %s is still %s after %d polls", name, state, attempt)
		}
		if err := p.wait(ctx, interval); err != nil {
			return nil, errors.WithMessagef(err, "key version %s is %s", name, state)
		}
	}
}

// wait pauses for d, or returns early with the cause when ctx is done or
// the provider is closing.
func (p *Provider) wait(ctx context.Context, d time.Duration) error {
	if p.sleep != nil {
		return p.sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	case <-p.closing:
		return errors.WithStack(ErrClosed)
	case <-timer.C:
		return nil
	}
}

// signerForVersion returns the signer of ver, which must be ENABLED with a
// supported signing algorithm (XPKI-019), after fetching its public key.
func (p *Provider) signerForVersion(ctx context.Context, ver *kmspb.CryptoKeyVersion, label string) (crypto.PrivateKey, error) {
	keyID := keyIDOfVersion(ver.GetName())
	if state := ver.GetState(); state != kmspb.CryptoKeyVersion_ENABLED {
		if reason := ver.GetGenerationFailureReason(); reason != "" {
			return nil, errors.Errorf("key version %s is %s: %s", keyID, state, reason)
		}
		return nil, errors.Errorf("key version %s is %s", keyID, state)
	}
	algorithm := ver.GetAlgorithm()
	if !supportsAlgorithm(algorithm) {
		return nil, errors.Errorf("unsupported key algorithm %s: %s", algorithm, keyID)
	}

	pub, err := p.publicKey(ctx, ver.GetName(), algorithm)
	if err != nil {
		return nil, err
	}

	return NewSigner(keyID, label, pub, algorithm, p), nil
}

// publicKey fetches and parses the public key of the version name, whose
// KMS algorithm is algorithm. A classical version is returned as PEM. An
// ML-DSA version must be requested in the NIST_PQC format (KMS returns an
// error otherwise) and comes back as the raw FIPS 204 encoding in
// public_key with a CRC32C, which is verified before the key is accepted.
func (p *Provider) publicKey(ctx context.Context, name string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.PublicKey, error) {
	scheme, isMLDSA := mldsaSchemes[algorithm]
	req := &kmspb.GetPublicKeyRequest{Name: name}
	if isMLDSA {
		req.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
	}
	resp, err := p.GetPublicKey(ctx, req)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key")
	}
	if resp == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to get public key")
	}
	if isMLDSA {
		return mldsaPublicKey(resp, scheme.params)
	}

	pub, err := parseKeyFromPEM([]byte(resp.GetPem()))
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}

	return pub, nil
}

// mldsaPublicKey decodes the NIST_PQC public key of resp as a key of params,
// accepting it only with a present, matching checksum (as Sign does for
// signatures, XPKI-023).
func mldsaPublicKey(resp *kmspb.PublicKey, params mldsa.Parameters) (*mldsa.PublicKey, error) {
	checksummed := resp.GetPublicKey()
	data := checksummed.GetData()
	if len(data) == 0 {
		return nil, errors.WithMessage(errEmptyResponse, "failed to get public key")
	}
	crc := checksummed.GetCrc32CChecksum()
	if crc == nil {
		return nil, errors.Errorf("public key has no checksum")
	}
	if int64(Crc32c(data)) != crc.GetValue() {
		return nil, errors.Errorf("public key corrupted in-transit")
	}
	pub, err := mldsa.NewPublicKey(params, data)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}
	return pub, nil
}

// publicKeyPEM returns the PEM public key of ver: as KMS returns it for a
// classical version, re-encoded from the NIST_PQC bytes for an ML-DSA one.
func (p *Provider) publicKeyPEM(ctx context.Context, ver *kmspb.CryptoKeyVersion) (string, error) {
	if _, isMLDSA := mldsaSchemes[ver.GetAlgorithm()]; isMLDSA {
		pub, err := p.publicKey(ctx, ver.GetName(), ver.GetAlgorithm())
		if err != nil {
			return "", err
		}
		pemKey, err := certutil.EncodePublicKeyToPEM(pub)
		if err != nil {
			return "", err
		}
		return string(pemKey), nil
	}
	resp, err := p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: ver.GetName()})
	if err != nil {
		return "", err
	}
	if resp.GetPem() == "" {
		return "", errors.WithStack(errEmptyResponse)
	}
	return resp.GetPem(), nil
}

func parseKeyFromPEM(bytes []byte) (any, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, errors.Errorf("invalid block type")
	}

	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return k, nil
}

// IdentifyKey returns key id and label for the given private key. It makes
// no RPC.
func (p *Provider) IdentifyKey(_ context.Context, priv crypto.PrivateKey) (keyID, label string, err error) {
	if s, ok := priv.(*Signer); ok {
		return s.KeyID(), s.Label(), nil
	}

	return "", "", errors.New("not supported key")
}

// GetKey returns the signer of the version that keyID names, "K" for the
// newest enabled version or "K/cryptoKeyVersions/N" (XPKI-020). The version
// must be ENABLED with a supported signing algorithm. A key or version KMS
// does not have is a wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	logger.KV(xlog.INFO, "keyID", keyID)

	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	ck, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: p.keyName(key)})
	if err != nil {
		return nil, kmsError(err, "failed to get key")
	}
	if ck == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to get key")
	}

	ver, err := p.enabledVersion(ctx, key, version)
	if err != nil {
		return nil, err
	}

	return p.signerForVersion(ctx, ver, ck.GetLabels()[labelKey])
}

// kmsError wraps a KMS error with a message, and marks a NOT_FOUND status as
// cryptoprov.ErrKeyNotFound. The gRPC status stays reachable.
func kmsError(err error, format string, args ...any) error {
	wrapped := errors.WithMessagef(err, format, args...)
	if status.Code(err) == codes.NotFound {
		return cryptoprov.MarkError(wrapped, cryptoprov.ErrKeyNotFound)
	}
	return wrapped
}

// ListKeys returns one page of the CryptoKeys of the key ring, one
// ListCryptoKeys request for a full page: KMS returns the whole key, so the
// Metadata and Tags groups cost nothing. The page size and the page token
// are those of KMS; a page can be shorter than req.PageSize because the
// conditions KMS did not evaluate are applied to it.
//
// A filter on the label matches the "label" label, which GenerateKey
// derives from the requested label (KeyLabelAndID), so the filter value is
// sanitized the same way (XPKI-129). Label, label prefix and tag conditions
// whose value is a plain label value are sent to KMS in the documented
// filter forms ("labels.k=v", "labels.label:v"); every condition is checked
// again on the returned keys, so a filter KMS treats differently changes the
// cost and not the result. Usage and type are read from the listed key.
//
// The state of an asymmetric key is the state of a version, which costs a
// ListCryptoKeyVersions per key: it is read only for
// cryptoprov.KeyFieldState or a States filter, and describes the version
// KeyInfo would. Without it State is set for a key with a primary version
// only, which symmetric keys have.
func (p *Provider) ListKeys(ctx context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "listkeys")

	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	cursor, err := cryptoprov.ParsePageToken(req)
	if err != nil {
		return nil, err
	}

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	filter := sanitizedFilter(&req.Filter)
	limit := req.Limit(cryptoprov.DefaultPageSize)
	logger.KV(xlog.DEBUG, "endpoint", p.endpoint, "limit", limit)

	it := p.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{
		Parent: p.keyring,
		Filter: pushdownFilter(filter),
	})
	if it == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to list keys")
	}
	var page []*kmspb.CryptoKey
	nextToken, err := iterator.NewPager(it, limit, cursor.Marker).NextPage(&page)
	if err != nil {
		if status.Code(err) == codes.InvalidArgument && cursor.Marker != "" {
			// KMS rejects a page token that is not its own
			return nil, cryptoprov.MarkError(errors.WithMessage(err, "failed to list keys"), cryptoprov.ErrInvalidPageToken)
		}
		return nil, errors.WithMessage(err, "failed to list keys")
	}

	// every condition but the state, which may cost a request per key
	stateless := *filter
	stateless.States = nil
	keys := make([]cryptoprov.KeyInfo, 0, len(page))
	for _, ck := range page {
		ki := keyInfo(ck)
		if stateless.Match(ki) {
			keys = append(keys, *ki)
		}
	}

	if req.Fields.Has(cryptoprov.KeyFieldState) || len(filter.States) > 0 {
		if err := p.listedStates(ctx, keys); err != nil {
			return nil, err
		}
		keys = slices.DeleteFunc(keys, func(ki cryptoprov.KeyInfo) bool {
			return !filter.Match(&ki)
		})
	}

	res := &cryptoprov.ListKeysResponse{Keys: keys}
	if nextToken != "" {
		res.NextPageToken, err = cryptoprov.NewPageToken(req, cryptoprov.PageCursor{Marker: nextToken})
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// listedStates sets the state and the version of the listed keys that have
// no primary version, listConcurrency version listings at a time. The first
// failure cancels the rest and is returned.
func (p *Provider) listedStates(ctx context.Context, keys []cryptoprov.KeyInfo) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, listConcurrency)
	for i := range keys {
		ki := &keys[i]
		if ki.State != "" {
			// the state of the primary version came with the key
			continue
		}
		sem <- struct{}{}
		if ctx.Err() != nil {
			<-sem
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			ver, state, err := p.describedVersion(ctx, ki.ID, "")
			if err != nil {
				once.Do(func() {
					firstErr = err
					cancel()
				})
				return
			}
			ki.State = state
			if ver != nil {
				setVersionInfo(ki, ver)
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return errors.WithStack(ctx.Err())
}

// describedVersion returns the version a KeyInfo of the CryptoKey key
// describes and its state: the named version, or for an empty version the
// newest ENABLED one, else the newest one not DESTROYED (XPKI-020,
// XPKI-117). A key whose versions are all destroyed has no such version and
// is destroyed; a key without versions is unavailable.
func (p *Provider) describedVersion(ctx context.Context, key, version string) (*kmspb.CryptoKeyVersion, cryptoprov.KeyState, error) {
	if version != "" {
		ver, err := p.getVersion(ctx, key, version)
		if err != nil {
			return nil, "", err
		}
		return ver, versionState(ver.GetState()), nil
	}
	versions, err := p.listVersions(ctx, key)
	if err != nil {
		return nil, "", err
	}
	ver := newestVersion(versions, isEnabled)
	if ver == nil {
		ver = newestVersion(versions, isNotDestroyed)
	}
	switch {
	case ver != nil:
		return ver, versionState(ver.GetState()), nil
	case len(versions) > 0:
		return nil, cryptoprov.KeyStateDestroyed, nil
	default:
		return nil, cryptoprov.KeyStateUnavailable, nil
	}
}

// versionState returns the cryptoprov state of a KMS version state.
func versionState(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) cryptoprov.KeyState {
	switch state {
	case kmspb.CryptoKeyVersion_ENABLED:
		return cryptoprov.KeyStateEnabled
	case kmspb.CryptoKeyVersion_DISABLED:
		return cryptoprov.KeyStateDisabled
	case kmspb.CryptoKeyVersion_DESTROY_SCHEDULED:
		return cryptoprov.KeyStatePendingDeletion
	case kmspb.CryptoKeyVersion_DESTROYED:
		return cryptoprov.KeyStateDestroyed
	default:
		return cryptoprov.KeyStateUnavailable
	}
}

// sanitizedFilter returns f with its label conditions in the form KMS
// stores a label: lower case, with every character outside [a-z0-9_-]
// replaced, cut to the label length.
func sanitizedFilter(f *cryptoprov.KeyFilter) *cryptoprov.KeyFilter {
	c := *f
	c.Label = sanitizeLabel(f.Label)
	c.LabelPrefix = sanitizeLabel(f.LabelPrefix)
	return &c
}

// pushdownFilter returns the ListCryptoKeys filter for the conditions of f
// that have a documented form: "labels.label=v" for the label,
// "labels.label:v" (a substring match) for a label prefix and "labels.k=v"
// for a tag, joined with AND. A value or a name that is not a plain label
// token is left to the check on the returned keys.
func pushdownFilter(f *cryptoprov.KeyFilter) string {
	var terms []string
	switch {
	case isLabelToken(f.Label):
		terms = append(terms, filterLabels+labelKey+"="+f.Label)
	case f.Label == "" && isLabelToken(f.LabelPrefix):
		terms = append(terms, filterLabels+labelKey+":"+f.LabelPrefix)
	}
	for _, name := range slices.Sorted(maps.Keys(f.Tags)) {
		if value := f.Tags[name]; isLabelToken(name) && isLabelToken(value) {
			terms = append(terms, filterLabels+name+"="+value)
		}
	}
	return strings.Join(terms, filterAnd)
}

// isLabelToken reports whether s is not empty and has only the characters
// of a plain label name or value, [a-z0-9_-], which need no quoting in a
// filter.
func isLabelToken(s string) bool {
	return s != "" && s == sanitizeName(s)
}

// keyIDVersion splits a key ID, "K" or "K/cryptoKeyVersions/N", into the
// CryptoKey id and the version, which is empty when the ID names none.
func keyIDVersion(keyID string) (key, version string, err error) {
	key, version, found := strings.Cut(keyID, versionsSegment)
	if key == "" || strings.Contains(key, "/") || (found && !isVersionNumber(version)) {
		return "", "", errors.Errorf("invalid key ID: %q", keyID)
	}
	return key, version, nil
}

// isVersionNumber reports whether v is a non-empty decimal number, as KMS
// version ids are.
func isVersionNumber(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// keyName returns the resource name of the CryptoKey key.
func (p *Provider) keyName(key string) string {
	return p.keyring + cryptoKeysSegment + key
}

// versionName returns the resource name of version of the CryptoKey keyName.
func versionName(keyName, version string) string {
	return keyName + versionsSegment + version
}

// keyIDOfVersion returns the key ID "K/cryptoKeyVersions/N" of a version
// resource name.
func keyIDOfVersion(name string) string {
	return path.Base(path.Dir(path.Dir(name))) + versionsSegment + path.Base(name)
}

// versionOf returns the version id of a version resource name, or "" for an
// empty name.
func versionOf(name string) string {
	if name == "" {
		return ""
	}
	return path.Base(name)
}

// getVersion fetches the version of the CryptoKey key.
func (p *Provider) getVersion(ctx context.Context, key, version string) (*kmspb.CryptoKeyVersion, error) {
	keyID := key + versionsSegment + version
	ver, err := p.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: versionName(p.keyName(key), version)})
	if err != nil {
		return nil, kmsError(err, "failed to get key version %s", keyID)
	}
	if ver == nil {
		return nil, errors.WithMessagef(errEmptyResponse, "failed to get key version %s", keyID)
	}
	return ver, nil
}

// keyVersion is a listed version with its parsed number.
type keyVersion struct {
	number uint64
	pb     *kmspb.CryptoKeyVersion
}

// listVersions returns the versions of the CryptoKey key, lowest number
// first.
func (p *Provider) listVersions(ctx context.Context, key string) ([]keyVersion, error) {
	iter := p.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: p.keyName(key),
	})
	if iter == nil {
		return nil, errors.WithMessagef(errEmptyResponse, "failed to list versions of key %s", key)
	}

	var versions []keyVersion
	for {
		ver, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, kmsError(err, "failed to list versions of key %s", key)
		}
		number, err := strconv.ParseUint(versionOf(ver.GetName()), 10, 64)
		if err != nil {
			return nil, errors.WithMessagef(err, "invalid version name %q of key %s", ver.GetName(), key)
		}
		versions = append(versions, keyVersion{number: number, pb: ver})
	}
	slices.SortFunc(versions, func(a, b keyVersion) int {
		return cmp.Compare(a.number, b.number)
	})
	return versions, nil
}

// newestVersion returns the highest-numbered version whose state accept
// reports, or nil.
func newestVersion(versions []keyVersion, accept func(kmspb.CryptoKeyVersion_CryptoKeyVersionState) bool) *kmspb.CryptoKeyVersion {
	for _, ver := range slices.Backward(versions) {
		if accept(ver.pb.GetState()) {
			return ver.pb
		}
	}
	return nil
}

func isEnabled(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) bool {
	return state == kmspb.CryptoKeyVersion_ENABLED
}

func isNotDestroyed(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) bool {
	return state != kmspb.CryptoKeyVersion_DESTROYED
}

// isDestroyable reports the states DestroyCryptoKeyVersion accepts.
func isDestroyable(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) bool {
	return state == kmspb.CryptoKeyVersion_ENABLED || state == kmspb.CryptoKeyVersion_DISABLED
}

// enabledVersion returns the version to sign with: the named version, or
// the newest ENABLED version of key when version is empty (XPKI-020). The
// caller checks the state of a named version.
func (p *Provider) enabledVersion(ctx context.Context, key, version string) (*kmspb.CryptoKeyVersion, error) {
	if version != "" {
		return p.getVersion(ctx, key, version)
	}
	versions, err := p.listVersions(ctx, key)
	if err != nil {
		return nil, err
	}
	ver := newestVersion(versions, isEnabled)
	if ver == nil {
		return nil, errors.Errorf("key %s has no enabled version", key)
	}
	return ver, nil
}

// DestroyKey schedules key material for destruction. A version id,
// "K/cryptoKeyVersions/N", destroys that version only; a bare "K" destroys
// every ENABLED or DISABLED version of the key, newest first, so the key can
// no longer sign (XPKI-020, XPKI-116). A key with no such version is an
// error. The first failure stops the loop. A key or version KMS does not
// have is a wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) DestroyKey(ctx context.Context, keyID string) error {
	logger.KV(xlog.NOTICE, "key", keyID)

	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.WithStack(err)
	}

	if err := p.enter(); err != nil {
		return err
	}
	defer p.exit()

	if version != "" {
		return p.destroyVersion(ctx, versionName(p.keyName(key), version))
	}

	versions, err := p.listVersions(ctx, key)
	if err != nil {
		return err
	}
	destroyed := 0
	for _, ver := range slices.Backward(versions) {
		if !isDestroyable(ver.pb.GetState()) {
			continue
		}
		if err := p.destroyVersion(ctx, ver.pb.GetName()); err != nil {
			return err
		}
		destroyed++
	}
	if destroyed == 0 {
		return errors.Errorf("key %s has no version to destroy", key)
	}
	return nil
}

// destroyVersion schedules the version resource name for destruction. A nil
// response is not a confirmation and is an error (XPKI-123).
func (p *Provider) destroyVersion(ctx context.Context, name string) error {
	versionID := keyIDOfVersion(name)
	resp, err := p.DestroyCryptoKeyVersion(ctx,
		&kmspb.DestroyCryptoKeyVersionRequest{
			Name: name,
		})
	if err != nil {
		return kmsError(err, "failed to schedule key deletion: %s", versionID)
	}
	if resp == nil {
		return errors.WithMessagef(errEmptyResponse, "failed to schedule key deletion: %s", versionID)
	}
	if destroyTime := resp.GetDestroyTime(); destroyTime != nil {
		logger.KV(xlog.NOTICE, "id", versionID, "deletion_time", destroyTime.AsTime())
	}
	return nil
}

// KeyInfo describes the key keyID with one GetCryptoKey, which supplies the
// Metadata and Tags groups. A version is read only when the call needs one:
// keyID names it ("K/cryptoKeyVersions/N", one GetCryptoKeyVersion), or
// fields has cryptoprov.KeyFieldState or cryptoprov.KeyFieldPublicKey and
// keyID is a bare id, which costs a version listing to find the newest
// ENABLED version, else the newest one not DESTROYED (XPKI-020, XPKI-117).
// That version supplies State, CurrentVersionID, the algorithm (Type, Size
// and the "algo" and "protection" Meta) and the public key. A key with no
// such version is described without version fields, and the public key is
// then an error. ID is keyID's CryptoKey id, with the version when keyID
// names one. A key or version KMS does not have is a wrapped
// cryptoprov.ErrKeyNotFound.
func (p *Provider) KeyInfo(ctx context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	if err := fields.Validate(); err != nil {
		return nil, err
	}
	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return nil, err
	}
	name := p.keyName(key)

	logger.KV(xlog.DEBUG, "key", name)
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	ck, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, kmsError(err, "failed to describe key, id=%s", keyID)
	}
	if ck == nil {
		return nil, errors.WithMessagef(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}
	res := keyInfo(ck)

	includePublic := fields.Has(cryptoprov.KeyFieldPublicKey)
	var ver *kmspb.CryptoKeyVersion
	if version != "" || includePublic || fields.Has(cryptoprov.KeyFieldState) {
		var state cryptoprov.KeyState
		if ver, state, err = p.describedVersion(ctx, key, version); err != nil {
			return nil, err
		}
		res.State = state
		if ver != nil {
			setVersionInfo(res, ver)
		}
	}
	if version != "" {
		res.ID = keyID
	}
	if includePublic {
		if ver == nil {
			return nil, errors.Errorf("key %s has no version with a public key", key)
		}
		pemKey, err := p.publicKeyPEM(ctx, ver)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
		}
		res.PublicKey = pemKey
	}

	return res, nil
}

// keyInfo converts key: ID and Name, the Metadata group, the labels as Tags
// and, for a key with a primary version, the State group. Optional metadata
// that KMS did not return is left out: no CreationTime without CreateTime,
// no Type, Size or "protection"/"algo" Meta without VersionTemplate
// (XPKI-023), and no CurrentVersionID, State or "state" without a primary
// version, which asymmetric keys do not have.
func keyInfo(key *kmspb.CryptoKey) *cryptoprov.KeyInfo {
	purpose := key.GetPurpose()
	ki := &cryptoprov.KeyInfo{
		ID:    path.Base(key.GetName()),
		Name:  key.GetName(),
		Label: key.GetLabels()[labelKey],
		Usage: purposeUsage(purpose),
		Tags:  maps.Clone(key.GetLabels()),

		Meta: map[string]string{
			metaPurpose: purpose.String(),
		},
	}
	if ct := key.GetCreateTime(); ct != nil {
		createdAt := ct.AsTime()
		ki.CreationTime = &createdAt
	}
	if vt := key.GetVersionTemplate(); vt != nil {
		ki.Meta[metaProtection] = vt.GetProtectionLevel().String()
		setAlgorithmInfo(ki, vt.GetAlgorithm())
	}
	if primary := key.GetPrimary(); primary != nil {
		ki.CurrentVersionID = versionOf(primary.GetName())
		ki.State = versionState(primary.GetState())
		ki.Meta[metaState] = primary.GetState().String()
	}

	return ki
}

// purposeUsage returns the cryptoprov usage of a CryptoKey purpose, and zero
// for a purpose other than signing and encryption (MAC, key encapsulation).
func purposeUsage(purpose kmspb.CryptoKey_CryptoKeyPurpose) cryptoprov.KeyUsage {
	switch purpose {
	case kmspb.CryptoKey_ASYMMETRIC_SIGN:
		return cryptoprov.KeyUsageSign
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT:
		return cryptoprov.KeyUsageEncrypt
	default:
		return 0
	}
}

// setVersionInfo records the selected version in ki: its id, state and,
// when KMS returned them, its algorithm and protection level.
func setVersionInfo(ki *cryptoprov.KeyInfo, ver *kmspb.CryptoKeyVersion) {
	ki.CurrentVersionID = versionOf(ver.GetName())
	ki.State = versionState(ver.GetState())
	ki.Meta[metaState] = ver.GetState().String()
	if algorithm := ver.GetAlgorithm(); algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		setAlgorithmInfo(ki, algorithm)
	}
	if protection := ver.GetProtectionLevel(); protection != kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED {
		ki.Meta[metaProtection] = protection.String()
	}
}

// setAlgorithmInfo records algorithm in ki: Meta "algo", Type and Size for
// the algorithms of an RSA key, of an ECDSA key on a NIST curve and of an
// ML-DSA key and, for ML-DSA, the parameter set under
// cryptoprov.MetaParameterSet. Any other algorithm (symmetric, MAC,
// secp256k1, Ed25519) leaves Type empty and Size zero.
func setAlgorithmInfo(ki *cryptoprov.KeyInfo, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) {
	name := algorithm.String()
	ki.Meta[metaAlgo] = name
	ki.Type, ki.Size = "", 0
	delete(ki.Meta, cryptoprov.MetaParameterSet)

	if scheme, ok := mldsaSchemes[algorithm]; ok {
		ki.Type = certutil.KeyTypeMLDSA
		ki.Size = cryptoprov.MLDSASize(scheme.params)
		ki.Meta[cryptoprov.MetaParameterSet] = scheme.params.String()
		return
	}
	for size, ecAlgorithm := range ecAlgorithms {
		if ecAlgorithm == algorithm {
			ki.Type = certutil.KeyTypeECDSA
			ki.Size = size
			return
		}
	}
	if strings.HasPrefix(name, rsaSignAlgorithmPrefix) || strings.HasPrefix(name, rsaDecryptAlgorithmPrefix) {
		ki.Type = certutil.KeyTypeRSA
		for part := range strings.SplitSeq(name, algorithmNameSeparator) {
			if size, err := strconv.Atoi(part); err == nil && size >= minRSAKeySize {
				ki.Size = size
				return
			}
		}
	}
}

// ExportKey returns the PKCS#11 URI of the key ID, without key bytes and
// without an RPC. The id attribute is keyID as given: a signer's key ID
// (from IdentifyKey) names its version, so the URI pins it; a bare id is
// resolved again when the URI is loaded (XPKI-020). serial is always 1.
func (p *Provider) ExportKey(_ context.Context, keyID string) (string, []byte, error) {
	if _, _, err := keyIDVersion(keyID); err != nil {
		return "", nil, err
	}

	uri := fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;id=%s;serial=%s;type=private",
		p.Manufacturer(),
		p.Model(),
		keyID,
		uriSerial,
	)

	return uri, []byte(uri), nil
}

// Close rejects new operations with ErrClosed, ends any wait for key
// generation, waits for the operations in flight, then closes the client and
// returns its error. Later and concurrent calls wait for the first one and
// return nil. The KmsClient field is kept (XPKI-018).
func (p *Provider) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = p.close()
	})
	return err
}

func (p *Provider) close() error {
	p.mu.Lock()
	p.closed = true
	if p.closing != nil {
		close(p.closing)
	}
	var drained chan struct{}
	if p.active > 0 {
		drained = make(chan struct{})
		p.drained = drained
	}
	p.mu.Unlock()

	if drained != nil {
		<-drained
	}
	if p.KmsClient == nil {
		return nil
	}
	return errors.WithMessage(p.KmsClient.Close(), "unable to close KMS client")
}

// KmsLoader provides loader for KMS provider
func KmsLoader(tc cryptoprov.TokenConfig) (cryptoprov.Provider, error) {
	p, err := Init(tc)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// KeyLabelAndID returns the KMS label and CryptoKey id for a requested key
// name. A trailing "*" is dropped. The label is the name lower-cased, with
// every character outside [a-z0-9_-] replaced by "-" and cut to 63
// characters, which KMS accepts as a label value. The id is the label cut to
// 54 characters, "-" and 8 random characters from crypto/rand (40 bits), so
// it is at most 63 characters and always keeps its random suffix
// (XPKI-022). For an empty name the id is the suffix alone.
func KeyLabelAndID(val string) (label string, id string) {
	label = sanitizeLabel(val)
	base := truncate(label, maxKeyIDLength-len(keyIDSeparator)-keyIDSuffixLength)
	suffix := strings.ToLower(rand.Text())[:keyIDSuffixLength]
	if base == "" {
		return label, suffix
	}

	return label, base + keyIDSeparator + suffix
}

// sanitizeLabel returns the label KMS stores for the requested label s: the
// label of KeyLabelAndID.
func sanitizeLabel(s string) string {
	return truncate(sanitizeName(strings.TrimSuffix(s, "*")), maxLabelLength)
}

// sanitizeName lower-cases s and replaces every character outside
// [a-z0-9_-] with "-".
func sanitizeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}

// truncate cuts the ASCII string s to at most n bytes.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Ensure compiles
var _ cryptoprov.Provider = (*Provider)(nil)
var _ cryptoprov.KeyManager = (*Provider)(nil)
