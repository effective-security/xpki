package gcpkmscrypto

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/guid"
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

// Provider implements Provider interface for KMS
type Provider struct {
	KmsClient

	tc       cryptoprov.TokenConfig
	endpoint string
	keyring  string
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

	attrs := strings.Split(attributes, ",")
	for _, v := range attrs {
		kmsAttr := strings.Split(v, "=")
		kmsAttributes[strings.TrimSpace(kmsAttr[0])] = strings.TrimSpace(kmsAttr[1])
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

func (p *Provider) genKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, label string) (crypto.PrivateKey, error) {
	resp, err := p.KmsClient.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create key")
	}

	logger.KV(xlog.NOTICE,
		"keyID", resp.Name,
		"label", label,
	)

	var pubKeyResp *kmspb.PublicKey
	// Retrieve public key from KMS
	for i := 0; i < 60; i++ {
		pubKeyResp, err = p.KmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: resp.Name + "/cryptoKeyVersions/1"})
		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "PENDING_GENERATION") {
			return nil, errors.WithMessagef(err, "failed to get public key")
		}
		time.Sleep(1 * time.Second)
	}

	pub, err := parseKeyFromPEM([]byte(pubKeyResp.Pem))
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

	ctx := context.Background()
	name := p.keyName(keyID)
	key, err := p.KmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get key")
	}

	pubResponse, err := p.KmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name + "/cryptoKeyVersions/1"})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key")
	}

	pub, err := parseKeyFromPEM([]byte(pubResponse.Pem))
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key")
	}
	signer := NewSigner(keyID, key.Labels["label"], pub, p)
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

	iter := p.KmsClient.ListCryptoKeys(
		context.Background(),
		&kmspb.ListCryptoKeysRequest{
			Parent: p.keyring,
		},
	)

	list := make([]cryptoprov.KeyInfo, 0)
	for {
		key, err := iter.Next()
		if err == iterator.Done {
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

func keyLabelInfo(key *kmspb.CryptoKey) string {
	label := "protection=" + key.VersionTemplate.ProtectionLevel.String()
	for k, v := range key.Labels {
		if label != "" {
			label += ","
		}
		label += k + "=" + v
	}
	return label
}

// DestroyKeyPairOnSlot destroys key pair on slot. For KMS slotID is ignored and KMS retire API is used to destroy the key.
func (p *Provider) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	logger.KV(xlog.NOTICE, "slot", slotID, "key", keyID)
	resp, err := p.KmsClient.DestroyCryptoKeyVersion(context.Background(),
		&kmspb.DestroyCryptoKeyVersionRequest{
			Name: p.keyVersionName(keyID),
		})
	if err != nil {
		return errors.WithMessagef(err, "failed to schedule key deletion: %s", keyID)
	}
	logger.KV(xlog.NOTICE, "id", keyID, "deletion_time", resp.DestroyTime.AsTime())

	return nil
}

// KeyInfo retrieves info about key with the specified id
func (p *Provider) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	ctx := context.Background()
	name := p.keyName(keyID)

	logger.KV(xlog.DEBUG, "key", name)

	key, err := p.KmsClient.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}

	res := keyInfo(key)
	if includePublic {
		pub, err := p.KmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name + "/cryptoKeyVersions/1"})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
		}
		res.PublicKey = pub.Pem
	}

	return res, nil
}

func keyInfo(key *kmspb.CryptoKey) *cryptoprov.KeyInfo {
	createdAt := key.CreateTime.AsTime()
	ki := &cryptoprov.KeyInfo{
		ID:               path.Base(key.Name),
		Label:            keyLabelInfo(key),
		CurrentVersionID: "1",
		CreationTime:     &createdAt,

		Meta: map[string]string{
			"protection": key.VersionTemplate.ProtectionLevel.String(),
			"algo":       key.VersionTemplate.Algorithm.String(),
			"purpose":    key.Purpose.String(),
		},
	}
	if key.Primary != nil {
		ki.Meta["state"] = key.Primary.State.String()
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

// Close allocated resources and file reloader
func (p *Provider) Close() error {
	if p.KmsClient != nil {
		p.KmsClient.Close()
		p.KmsClient = nil
	}
	return nil
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
	g := guid.MustCreate()
	label = strings.ToLower(strings.TrimSuffix(val, "*"))
	id = label + strings.ToLower(g[:4])

	if len(id) > 63 {
		id = id[:63]
	}

	return
}

// Ensure compiles
var _ cryptoprov.Provider = (*Provider)(nil)
var _ cryptoprov.KeyManager = (*Provider)(nil)
