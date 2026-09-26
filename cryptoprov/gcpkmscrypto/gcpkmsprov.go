package gcpkmscrypto

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/metricskey"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki/cryptoprov", "gcpkms")

// ProviderName specifies a provider name
const ProviderName = "GCPKMS"

func init() {
	_ = cryptoprov.Register(ProviderName, KmsLoader)
}

// KmsClient interface
type KmsClient interface {
	ListCryptoKeys(context.Context, *kmspb.ListCryptoKeysRequest, ...gax.CallOption) *kms.CryptoKeyIterator
	GetCryptoKey(context.Context, *kmspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	GetPublicKey(context.Context, *kmspb.GetPublicKeyRequest, ...gax.CallOption) (*kmspb.PublicKey, error)
	GetCryptoKeyVersion(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	DestroyCryptoKeyVersion(context.Context, *kmspb.DestroyCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error)
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest, ...gax.CallOption) (*kmspb.CryptoKey, error)
	Close() error
}

// KmsClientFactory override for unittest
var KmsClientFactory = func() (KmsClient, error) {
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create kms client")
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
// Its methods and signers are safe for concurrent use with Close: Close
// rejects new operations with ErrClosed, waits for those in flight, then
// closes the client. The embedded KmsClient is set up by Init; its methods
// called directly bypass that guard.
type Provider struct {
	KmsClient

	tc       cryptoprov.TokenConfig
	endpoint string
	keyring  string

	mu        sync.Mutex
	active    int
	closed    bool
	drained   chan struct{}
	closeOnce sync.Once
}

// Init configures Kms based hsm impl
func Init(tc cryptoprov.TokenConfig) (*Provider, error) {
	kmsAttributes := parseKmsAttributes(tc.Attributes())
	endpoint := kmsAttributes["Endpoint"]
	keyring := kmsAttributes["Keyring"]

	p := &Provider{
		endpoint: endpoint,
		keyring:  keyring,
		tc:       tc,
	}

	var err error
	p.KmsClient, err = KmsClientFactory()
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create KMS client")
	}

	return p, nil
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

// GenerateRSAKey creates signer using randomly generated RSA key
func (p *Provider) GenerateRSAKey(label string, bits int, purpose int) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_rsa")

	ctx := context.Background()

	pbpurpose := kmspb.CryptoKey_ASYMMETRIC_SIGN
	if purpose == 2 {
		pbpurpose = kmspb.CryptoKey_ASYMMETRIC_DECRYPT
	}

	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch bits {
	case 2048:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
	case 3072:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
	case 4096:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
	default:
		return nil, errors.Errorf("unsupported key size: %d", bits)
	}

	label, keyID := KeyLabelAndID(label)
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      p.keyring,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: pbpurpose,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       algorithm,
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
			},
			Labels: map[string]string{
				"label": label,
			},
		},
	}
	return p.genKey(ctx, req, label)
}

// genKey creates the key of req and waits for its public key. Close waits
// for it, including the wait for key generation.
func (p *Provider) genKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, label string) (crypto.PrivateKey, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	resp, err := p.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create key")
	}
	if resp == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to create key")
	}

	logger.KV(xlog.NOTICE,
		"keyID", resp.Name,
		"label", label,
	)

	var pubKeyResp *kmspb.PublicKey
	// Retrieve public key from KMS
	for i := 0; i < 60; i++ {
		pubKeyResp, err = p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: resp.Name + "/cryptoKeyVersions/1"})
		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "PENDING_GENERATION") {
			return nil, errors.WithMessagef(err, "failed to get public key")
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return nil, errors.WithMessagef(err, "public key is not available")
	}

	pub, err := parseKeyFromPEM([]byte(pubKeyResp.GetPem()))
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}
	signer := NewSigner(path.Base(resp.Name), label, pub, p)

	return signer, nil
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

// GenerateECDSAKey creates signer using randomly generated ECDSA key
func (p *Provider) GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_ecdsa")

	ctx := context.Background()

	pbpurpose := kmspb.CryptoKey_ASYMMETRIC_SIGN
	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm

	switch curve {
	case elliptic.P256():
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case elliptic.P384():
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
	//case elliptic.P521():
	//  algorithm = CryptoKeyVersion_EC_SIGN_P521_SHA512
	default:
		return nil, errors.New("unsupported curve")
	}

	label, keyID := KeyLabelAndID(label)
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      p.keyring,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: pbpurpose,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       algorithm,
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
			},
			Labels: map[string]string{
				"label": label,
			},
		},
	}
	return p.genKey(ctx, req, label)
}

// IdentifyKey returns key id and label for the given private key
func (p *Provider) IdentifyKey(priv crypto.PrivateKey) (keyID, label string, err error) {
	if s, ok := priv.(*Signer); ok {
		return s.KeyID(), s.Label(), nil
	}

	return "", "", errors.New("not supported key")
}

// GetKey returns PrivateKey
func (p *Provider) GetKey(keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	logger.KV(xlog.INFO, "keyID", keyID)

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	ctx := context.Background()
	name := p.keyName(keyID)
	key, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get key")
	}
	if key == nil {
		return nil, errors.WithMessage(errEmptyResponse, "failed to get key")
	}

	pubResponse, err := p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name + "/cryptoKeyVersions/1"})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key")
	}

	pub, err := parseKeyFromPEM([]byte(pubResponse.GetPem()))
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}
	signer := NewSigner(keyID, key.GetLabels()["label"], pub, p)
	return signer, nil
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

func (p *Provider) keyName(keyID string) string {
	return p.keyring + "/cryptoKeys/" + keyID
}

func (p *Provider) keyVersionName(keyID string) string {
	return p.keyring + "/cryptoKeys/" + keyID + "/cryptoKeyVersions/1"
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

// DestroyKeyPairOnSlot destroys key pair on slot. For KMS slotID is ignored and KMS retire API is used to destroy the key.
func (p *Provider) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	logger.KV(xlog.NOTICE, "slot", slotID, "key", keyID)
	if err := p.enter(); err != nil {
		return err
	}
	defer p.exit()

	resp, err := p.DestroyCryptoKeyVersion(context.Background(),
		&kmspb.DestroyCryptoKeyVersionRequest{
			Name: p.keyVersionName(keyID),
		})
	if err != nil {
		return errors.WithMessagef(err, "failed to schedule key deletion: %s", keyID)
	}
	if destroyTime := resp.GetDestroyTime(); destroyTime != nil {
		logger.KV(xlog.NOTICE, "id", keyID, "deletion_time", destroyTime.AsTime())
	}

	return nil
}

// KeyInfo retrieves info about key with the specified id
func (p *Provider) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	ctx := context.Background()
	name := p.keyName(keyID)

	logger.KV(xlog.DEBUG, "key", name)

	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.exit()

	key, err := p.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}
	if key == nil {
		return nil, errors.WithMessagef(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}

	res := keyInfo(key)
	if includePublic {
		pub, err := p.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name + "/cryptoKeyVersions/1"})
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
// out: no CreationTime without CreateTime, and no "protection"/"algo" Meta
// without VersionTemplate (XPKI-023).
func keyInfo(key *kmspb.CryptoKey) *cryptoprov.KeyInfo {
	ki := &cryptoprov.KeyInfo{
		ID:               path.Base(key.GetName()),
		Label:            keyLabelInfo(key),
		CurrentVersionID: "1",

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
		ki.Meta["state"] = primary.GetState().String()
	}

	return ki
}

// ExportKey returns PKCS#11 URI for specified key ID.
// It does not return key bytes
func (p *Provider) ExportKey(keyID string) (string, []byte, error) {
	uri := fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;id=%s;serial=1;type=private",
		p.Manufacturer(),
		p.Model(),
		keyID,
	)

	return uri, []byte(uri), nil
}

// FindKeyPairOnSlot retrieves a previously created asymmetric key, using a specified slot.
func (p *Provider) FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error) {
	return nil, errors.Errorf("unsupported command for this crypto provider")
}

// Close rejects new operations with ErrClosed, waits for the operations in
// flight, then closes the client and returns its error. Later and
// concurrent calls wait for the first one and return nil. The KmsClient
// field is kept (XPKI-018).
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

// KeyLabelAndID adds a date suffix to ID of a key
func KeyLabelAndID(val string) (label string, id string) {
	// TODO: use a better 4 bytes random string or time based value?
	g := uuid.NewV4().String()
	label = strings.ToLower(strings.TrimSuffix(val, "*"))
	id = label + strings.ToLower(g[0:4])

	if len(id) > 63 {
		id = id[:63]
	}

	return
}

// Ensure compiles
var _ cryptoprov.Provider = (*Provider)(nil)
var _ cryptoprov.KeyManager = (*Provider)(nil)
