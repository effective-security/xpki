package gcpkmscrypto

import (
	"cmp"
	"context"
	"crypto"
	"crypto/elliptic"
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
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/metricskey"
	"github.com/googleapis/gax-go/v2"
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

	// purposeEncryption is the GenerateRSAKey purpose of an encryption key,
	// which this provider does not support (XPKI-019); every other value is
	// a signing key, as in the other providers (XPKI-118).
	purposeEncryption = 2

	// readyPollInterval and readyPollAttempts bound the wait for a new key
	// version to leave PENDING_GENERATION (XPKI-024).
	readyPollInterval = time.Second
	readyPollAttempts = 60

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
// GetKey, KeyInfo, EnumKeys, DestroyKeyPairOnSlot, GenerateRSAKey,
// GenerateECDSAKey and Signer.Sign. Operations that do not call KMS, such as
// EnumTokens, ExportKey and IdentifyKey, keep working.
var ErrClosed = errors.New("gcpkms: provider is closed")

// errEmptyResponse is returned when KMS returns neither a response nor an
// error.
var errEmptyResponse = errors.New("empty response")

// Provider implements Provider interface for KMS.
//
// A key ID is a CryptoKey id, "K", or one of its versions,
// "K/cryptoKeyVersions/N" (XPKI-020). GetKey, KeyInfo and
// DestroyKeyPairOnSlot use the named version. A bare id is resolved at each
// call: GetKey signs with the newest ENABLED version (none is an error),
// KeyInfo describes the newest ENABLED version, else the newest one not
// DESTROYED, else the key alone (XPKI-117), and DestroyKeyPairOnSlot
// schedules every ENABLED or DISABLED version for destruction (XPKI-116).
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

// CurrentSlotID returns current slot id. For KMS only one slot is assumed to be available.
func (p *Provider) CurrentSlotID() uint {
	return 0
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

// GenerateRSAKey creates a signer using a newly generated RSA signing key.
// This provider has no decrypter, so the encryption purpose (2) is an error
// before any RPC (XPKI-019); any other purpose is a signing key. The KMS
// algorithm is PKCS#1 v1.5 with SHA-256 for 2048 and 3072 bits and SHA-512
// for 4096 bits, and Sign accepts only that hash.
func (p *Provider) GenerateRSAKey(label string, bits int, purpose int) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_rsa")

	if purpose == purposeEncryption {
		return nil, errors.Errorf("unsupported key purpose: %d, only signing keys are supported", purpose)
	}

	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch bits {
	case 2048:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
	case 3072:
		// KMS has no SHA-384 algorithm for 3072-bit keys; csr.DefaultSigAlgo
		// follows Signer.SignatureAlgorithm, so CSRs and certificates are
		// signed with SHA-256 (XPKI-114).
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
	case 4096:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
	default:
		return nil, errors.Errorf("unsupported key size: %d", bits)
	}

	return p.genKey(context.Background(), label, algorithm)
}

// GenerateECDSAKey creates a signer using a newly generated ECDSA signing
// key: P-256 with SHA-256 or P-384 with SHA-384.
func (p *Provider) GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_ecdsa")

	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch curve {
	case elliptic.P256():
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case elliptic.P384():
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
	// KMS has no P-521 signing algorithm.
	default:
		return nil, errors.New("unsupported curve")
	}

	return p.genKey(context.Background(), label, algorithm)
}

// genKey creates an HSM signing key with algorithm, named after label by
// KeyLabelAndID, waits for its first version and returns its signer. When
// KMS reports that the key id exists, it tries new ids, createAttempts in
// all (XPKI-022). Close waits for it, but ends its wait for key generation.
func (p *Provider) genKey(ctx context.Context, name string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.PrivateKey, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	var resp *kmspb.CryptoKey
	var label string
	for attempt := 1; ; attempt++ {
		var keyID string
		label, keyID = KeyLabelAndID(name)
		req := &kmspb.CreateCryptoKeyRequest{
			Parent:      p.keyring,
			CryptoKeyId: keyID,
			CryptoKey: &kmspb.CryptoKey{
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					Algorithm:       algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_HSM,
				},
				Labels: map[string]string{
					labelKey: label,
				},
			},
		}

		var err error
		resp, err = p.CreateCryptoKey(ctx, req)
		if err == nil {
			break
		}
		if status.Code(err) != codes.AlreadyExists || attempt >= createAttempts {
			return nil, errors.WithMessagef(err, "failed to create key %s", keyID)
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

	ver, err := p.waitForVersion(ctx, versionName(resp.GetName(), firstVersion))
	if err != nil {
		return nil, err
	}

	return p.signerForVersion(ctx, ver, label)
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
	if _, ok := signSchemes[algorithm]; !ok {
		return nil, errors.Errorf("unsupported key algorithm %s: %s", algorithm, keyID)
	}

	pub, err := p.publicKey(ctx, ver.GetName())
	if err != nil {
		return nil, err
	}

	return NewSigner(keyID, label, pub, algorithm, p), nil
}

// publicKey fetches and parses the public key of the version name.
func (p *Provider) publicKey(ctx context.Context, name string) (crypto.PublicKey, error) {
	resp, err := p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key")
	}
	if resp == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to get public key")
	}

	pub, err := parseKeyFromPEM([]byte(resp.GetPem()))
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}

	return pub, nil
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

// IdentifyKey returns key id and label for the given private key
func (p *Provider) IdentifyKey(priv crypto.PrivateKey) (keyID, label string, err error) {
	if s, ok := priv.(*Signer); ok {
		return s.KeyID(), s.Label(), nil
	}

	return "", "", errors.New("not supported key")
}

// GetKey returns the signer of the version that keyID names, "K" for the
// newest enabled version or "K/cryptoKeyVersions/N" (XPKI-020). The version
// must be ENABLED with a supported signing algorithm.
func (p *Provider) GetKey(keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	logger.KV(xlog.INFO, "keyID", keyID)

	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return nil, err
	}

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	ctx := context.Background()
	ck, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: p.keyName(key)})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get key")
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

// EnumTokens lists tokens. For KMS currentSlotOnly is ignored and only one slot is assumed to be available.
func (p *Provider) EnumTokens(currentSlotOnly bool) ([]cryptoprov.TokenInfo, error) {
	return []cryptoprov.TokenInfo{
		{
			SlotID:       p.CurrentSlotID(),
			Manufacturer: p.Manufacturer(),
			Model:        p.Model(),
		},
	}, nil
}

// EnumKeys returns list of keys on the slot. For KMS slotID is ignored.
// Versions are not listed: CurrentVersionID is set only for keys with a
// primary version, which asymmetric keys do not have.
func (p *Provider) EnumKeys(slotID uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	logger.KV(xlog.DEBUG, "endpoint", p.endpoint, "slotID", slotID, "prefix", prefix)

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	iter := p.ListCryptoKeys(
		context.Background(),
		&kmspb.ListCryptoKeysRequest{
			Parent: p.keyring,
		},
	)
	if iter == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to list keys")
	}

	list := make([]cryptoprov.KeyInfo, 0)
	for {
		key, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}

		if key.Primary != nil &&
			key.Primary.State != kmspb.CryptoKeyVersion_ENABLED {
			logger.KV(xlog.DEBUG, "skip_key", key.Name, "state", key.Primary.State.String())
			continue
		}

		list = append(list, *keyInfo(key))
	}
	return list, nil
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
		return nil, errors.WithMessagef(err, "failed to get key version %s", keyID)
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
			return nil, errors.WithMessagef(err, "failed to list versions of key %s", key)
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

// keyLabelInfo returns "protection=LEVEL" when the key has a version
// template, followed by the key's labels sorted by name, comma separated.
func keyLabelInfo(key *kmspb.CryptoKey) string {
	var parts []string
	if vt := key.GetVersionTemplate(); vt != nil {
		parts = append(parts, "protection="+vt.GetProtectionLevel().String())
	}
	labels := key.GetLabels()
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}

// DestroyKeyPairOnSlot schedules key material for destruction. A version
// id, "K/cryptoKeyVersions/N", destroys that version only; a bare "K"
// destroys every ENABLED or DISABLED version of the key, newest first, so
// the key can no longer sign (XPKI-020, XPKI-116). A key with no such version
// is an error. The first failure stops the loop. slotID is ignored.
func (p *Provider) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	logger.KV(xlog.NOTICE, "slot", slotID, "key", keyID)

	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return err
	}

	if err := p.enter(); err != nil {
		return err
	}
	defer p.exit()

	ctx := context.Background()
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
		return errors.WithMessagef(err, "failed to schedule key deletion: %s", versionID)
	}
	if resp == nil {
		return errors.WithMessagef(errEmptyResponse, "failed to schedule key deletion: %s", versionID)
	}
	if destroyTime := resp.GetDestroyTime(); destroyTime != nil {
		logger.KV(xlog.NOTICE, "id", versionID, "deletion_time", destroyTime.AsTime())
	}
	return nil
}

// KeyInfo retrieves info about the key with the specified id. The described
// version supplies CurrentVersionID, the state, algo and protection Meta
// and, with includePublic, the public key: the version keyID names, or for a
// bare id the newest ENABLED version, else the newest one not DESTROYED
// (XPKI-020, XPKI-117). A key with no such version is described without
// version fields, and includePublic is then an error.
func (p *Provider) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	key, version, err := keyIDVersion(keyID)
	if err != nil {
		return nil, err
	}
	name := p.keyName(key)

	logger.KV(xlog.DEBUG, "key", name)

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	ctx := context.Background()
	ck, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}
	if ck == nil {
		return nil, errors.WithMessagef(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}

	var ver *kmspb.CryptoKeyVersion
	if version != "" {
		if ver, err = p.getVersion(ctx, key, version); err != nil {
			return nil, err
		}
	} else {
		versions, err := p.listVersions(ctx, key)
		if err != nil {
			return nil, err
		}
		if ver = newestVersion(versions, isEnabled); ver == nil {
			ver = newestVersion(versions, isNotDestroyed)
		}
	}

	res := keyInfo(ck)
	if ver != nil {
		setVersionInfo(res, ver)
	}
	if includePublic {
		if ver == nil {
			return nil, errors.Errorf("key %s has no version with a public key", key)
		}
		pub, err := p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: ver.GetName()})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
		}
		if pub.GetPem() == "" {
			return nil, errors.WithMessagef(errEmptyResponse, "failed to get public key, id=%s", keyID)
		}
		res.PublicKey = pub.GetPem()
	}

	return res, nil
}

// keyInfo converts key. Optional metadata that KMS did not return is left
// out: no CreationTime without CreateTime, no "protection"/"algo" Meta
// without VersionTemplate (XPKI-023), and no CurrentVersionID or "state"
// without a primary version.
func keyInfo(key *kmspb.CryptoKey) *cryptoprov.KeyInfo {
	ki := &cryptoprov.KeyInfo{
		ID:    path.Base(key.GetName()),
		Label: keyLabelInfo(key),

		Meta: map[string]string{
			"purpose": key.GetPurpose().String(),
		},
	}
	if ct := key.GetCreateTime(); ct != nil {
		createdAt := ct.AsTime()
		ki.CreationTime = &createdAt
	}
	if vt := key.GetVersionTemplate(); vt != nil {
		ki.Meta["protection"] = vt.GetProtectionLevel().String()
		ki.Meta["algo"] = vt.GetAlgorithm().String()
	}
	if primary := key.GetPrimary(); primary != nil {
		ki.CurrentVersionID = versionOf(primary.GetName())
		ki.Meta["state"] = primary.GetState().String()
	}

	return ki
}

// setVersionInfo records the selected version in ki: its id, state and,
// when KMS returned them, its algorithm and protection level.
func setVersionInfo(ki *cryptoprov.KeyInfo, ver *kmspb.CryptoKeyVersion) {
	ki.CurrentVersionID = versionOf(ver.GetName())
	ki.Meta["state"] = ver.GetState().String()
	if algorithm := ver.GetAlgorithm(); algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		ki.Meta["algo"] = algorithm.String()
	}
	if protection := ver.GetProtectionLevel(); protection != kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED {
		ki.Meta["protection"] = protection.String()
	}
}

// ExportKey returns the PKCS#11 URI of the key ID, without key bytes and
// without an RPC. The id attribute is keyID as given: a signer's key ID
// (from IdentifyKey) names its version, so the URI pins it; a bare id is
// resolved again when the URI is loaded (XPKI-020). serial is always 1.
func (p *Provider) ExportKey(keyID string) (string, []byte, error) {
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

// FindKeyPairOnSlot retrieves a previously created asymmetric key, using a specified slot.
func (p *Provider) FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error) {
	return nil, errors.Errorf("unsupported command for this crypto provider")
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
	label = truncate(sanitizeName(strings.TrimSuffix(val, "*")), maxLabelLength)
	base := truncate(label, maxKeyIDLength-len(keyIDSeparator)-keyIDSuffixLength)
	suffix := strings.ToLower(rand.Text())[:keyIDSuffixLength]
	if base == "" {
		return label, suffix
	}

	return label, base + keyIDSeparator + suffix
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
