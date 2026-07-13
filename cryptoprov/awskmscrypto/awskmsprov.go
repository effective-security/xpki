package awskmscrypto

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/metricskey"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "awskmscrypto")

// ProviderName specifies a provider name
const ProviderName = "AWSKMS"

func init() {
	_ = cryptoprov.Register(ProviderName, KmsLoader)
}

// KmsClient interface
type KmsClient interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(context.Context, *kms.CreateAliasInput, ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	//IdentifyKey(priv crypto.PrivateKey) (keyID, label string, err error)
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KmsClientFactory override for unittest
var KmsClientFactory = func(cfg aws.Config, optFns ...func(*kms.Options)) KmsClient {
	return kms.NewFromConfig(cfg, optFns...)
}

// Provider implements Provider interface for KMS
type Provider struct {
	tc        cryptoprov.TokenConfig
	kmsClient KmsClient
	endpoint  string
	region    string
}

// Init configures Kms based hsm impl
func Init(tc cryptoprov.TokenConfig) (*Provider, error) {
	ctx := context.Background()
	kmsAttributes := parseKmsAttributes(tc.Attributes())
	endpoint := kmsAttributes["Endpoint"]
	region := kmsAttributes["Region"]

	p := &Provider{
		endpoint: endpoint,
		region:   region,
		tc:       tc,
	}

	var awsops []func(*awsconfig.LoadOptions) error

	if region != "" {
		awsops = append(awsops, awsconfig.WithRegion(region))
	}
	id := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	token := os.Getenv("AWS_SESSION_TOKEN")
	if id != "" && secret != "" {
		awsops = append(awsops, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, token)))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsops...)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var kmsops []func(*kms.Options)
	if endpoint != "" {
		// Use service-specific endpoint resolution via BaseEndpoint.
		// https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/endpoints/
		kmsops = append(kmsops, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	p.kmsClient = KmsClientFactory(cfg, kmsops...)

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

	usage := values.Select(purpose == 2, types.KeyUsageTypeEncryptDecrypt, types.KeyUsageTypeSignVerify)
	specuKeyPairSpec := fmt.Sprintf("RSA_%d", bits)

	// 1. Create key in KMS
	input := &kms.CreateKeyInput{
		CustomerMasterKeySpec: types.CustomerMasterKeySpec(specuKeyPairSpec),
		KeyUsage:              usage,
		Description:           &label,
	}
	resp, err := p.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create key with label: %q", label)
	}

	keyID := aws.ToString(resp.KeyMetadata.KeyId)
	arn := aws.ToString(resp.KeyMetadata.Arn)
	logger.KV(xlog.INFO, "arn", arn, "id", keyID, "label", label)

	if label != "" {
		_, err := p.createAlias(ctx, keyID, label)
		if err != nil {
			logger.KV(xlog.WARNING, "reason", "CreateAlias", "id", keyID, "err", err.Error())
		}
	}

	// 2. Retrieve public key from KMS
	pubKeyResp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyResp.PublicKey)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
	}
	signer := NewSigner(keyID, label, resp.KeyMetadata.SigningAlgorithms, pub, p.kmsClient)

	return signer, nil
}

// GenerateECDSAKey creates signer using randomly generated ECDSA key
func (p *Provider) GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_ecdsa")

	ctx := context.Background()

	var spec types.CustomerMasterKeySpec
	switch curve {
	case elliptic.P256():
		spec = types.CustomerMasterKeySpecEccNistP256
	case elliptic.P384():
		spec = types.CustomerMasterKeySpecEccNistP384
	case elliptic.P521():
		spec = types.CustomerMasterKeySpecEccNistP521
	default:
		return nil, errors.New("unsupported curve")
	}

	// 1. Create key in KMS
	input := &kms.CreateKeyInput{
		CustomerMasterKeySpec: spec,
		KeyUsage:              types.KeyUsageTypeSignVerify,
		Description:           &label,
	}
	resp, err := p.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create key with label: %q", label)
	}

	keyID := aws.ToString(resp.KeyMetadata.KeyId)
	arn := aws.ToString(resp.KeyMetadata.Arn)
	logger.KV(xlog.INFO, "arn", arn, "id", keyID, "label", label)
	if label != "" {
		_, err := p.createAlias(ctx, keyID, label)
		if err != nil {
			logger.KV(xlog.WARNING, "reason", "CreateAlias", "id", keyID, "err", err.Error())
		}
	}

	// 2. Retrieve public key from KMS
	pubKeyResp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyResp.PublicKey)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
	}
	signer := NewSigner(keyID, label, resp.KeyMetadata.SigningAlgorithms, pub, p.kmsClient)

	return signer, nil
}

// aliasFromLabel builds a KMS-valid alias name ("alias/<sanitized-label>") from
// the provided label. KMS aliases only allow [a-zA-Z0-9:/_-]; any other rune is
// replaced with '_'. The reserved "alias/aws/" prefix is avoided.
func aliasFromLabel(label string) string {
	replace := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '/', r == '_', r == '-', r == ':':
			return r
		default:
			return '_'
		}
	}
	name := strings.TrimPrefix(strings.Map(replace, label), "aws/")
	return "alias/" + name
}

// createAlias creates a KMS alias for the given key using the provided label.
// The key already exists at this point, so an alias failure is logged as a
// warning and treated as non-fatal. It returns the alias name that was used.
func (p *Provider) createAlias(ctx context.Context, keyID, label string) (string, error) {
	alias := aliasFromLabel(label)
	if alias == "alias/" {
		return "", errors.New("alias is empty")
	}
	if _, err := p.kmsClient.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(alias),
		TargetKeyId: aws.String(keyID),
	}); err != nil {
		return "", errors.WithMessagef(err, "failed to create alias, id=%s, alias=%s", keyID, alias)
	}
	logger.KV(xlog.INFO, "id", keyID, "label", label, "alias", alias)
	return alias, nil
}

// IdentifyKey returns key id and label for the given private key
func (p *Provider) IdentifyKey(priv crypto.PrivateKey) (keyID, label string, err error) {
	if s, ok := priv.(*Signer); ok {
		return s.KeyID(), s.Label(), nil
	}
	return "", "", errors.New("not supported key")
}

// GetKey returns pkcs11 uri for the given key id
func (p *Provider) GetKey(keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	ctx := context.Background()
	logger.KV(xlog.INFO, "api", "GetKey", "keyID", keyID)

	ki, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}

	resp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
	}

	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
	}
	signer := NewSigner(keyID, aws.ToString(ki.KeyMetadata.Description), resp.SigningAlgorithms, pub, p.kmsClient)
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

func keyMeta(ki *kms.DescribeKeyOutput) map[string]string {
	return map[string]string{
		"description": aws.ToString(ki.KeyMetadata.Description),
		"usage":       string(ki.KeyMetadata.KeyUsage),
		"origin":      string(ki.KeyMetadata.Origin),
		"state":       string(ki.KeyMetadata.KeyState),
		"enabled":     fmt.Sprintf("%t", ki.KeyMetadata.Enabled),
		"algo":        fmt.Sprintf("%v", ki.KeyMetadata.SigningAlgorithms),
	}
}

// EnumKeys returns list of keys on the slot. For KMS slotID is ignored.
func (p *Provider) EnumKeys(slotID uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	logger.KV(xlog.DEBUG, "endpoint", p.endpoint, "slotID", slotID, "prefix", prefix)

	ctx := context.Background()
	opts := &kms.ListKeysInput{
		Limit: aws.Int32(100),
	}

	totalKeys := 0
	signKeys := 0
	res := make([]cryptoprov.KeyInfo, 0, 1000)
	for {
		resp, err := p.kmsClient.ListKeys(ctx, opts)
		if err != nil {
			return nil, err
		}

		keys := resp.Keys
		totalKeys += len(keys)
		for _, k := range keys {
			ki, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil {
				// return nil, errors.WithMessagef(err, "failed to describe key, id=%s, arn=%s", aws.ToString(k.KeyId), aws.ToString(k.KeyArn))
				logger.KV(xlog.ERROR,
					"reason", "DescribeKey",
					"id", aws.ToString(k.KeyId),
					"arn", aws.ToString(k.KeyArn),
					"error", err.Error(),
				)
				continue
			}
			if ki.KeyMetadata.KeyState == types.KeyStatePendingDeletion {
				continue
			}
			if ki.KeyMetadata.KeyUsage != types.KeyUsageTypeSignVerify {
				continue
			}
			signKeys++

			res = append(res, cryptoprov.KeyInfo{
				ID:           aws.ToString(k.KeyId),
				Meta:         keyMeta(ki),
				CreationTime: ki.KeyMetadata.CreationDate,
			})
		}

		if !resp.Truncated {
			break
		}
		opts.Marker = resp.NextMarker
	}
	logger.KV(xlog.DEBUG, "total_keys", totalKeys, "sign_keys", signKeys)

	return res, nil
}

// DestroyKeyPairOnSlot destroys key pair on slot. For KMS slotID is ignored and KMS retire API is used to destroy the key.
func (p *Provider) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	ctx := context.Background()
	resp, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: &keyID,
	})
	if err != nil {
		return errors.WithMessagef(err, "failed to schedule key deletion: %s", keyID)
	}
	logger.KV(xlog.NOTICE, "id", keyID, "deletion_time", aws.ToTime(resp.DeletionDate).Format(time.RFC3339))

	return nil
}

// KeyInfo retrieves info about key with the specified id
func (p *Provider) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	ctx := context.Background()
	resp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}

	pubKey := ""
	if includePublic {
		pubKeyResp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
		}
		pub, err := x509.ParsePKIXPublicKey(pubKeyResp.PublicKey)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
		}
		pemKey, err := certutil.EncodePublicKeyToPEM(pub)
		if err != nil {
			return nil, err
		}
		pubKey = string(pemKey)
		//		pubKey = base64.StdEncoding.EncodeToString(pub.PublicKey)
	}

	res := &cryptoprov.KeyInfo{
		ID:           keyID,
		PublicKey:    pubKey,
		Meta:         keyMeta(resp),
		CreationTime: resp.KeyMetadata.CreationDate,
	}
	if err != nil {
		return nil, err
	}

	return res, nil
}

// ExportKey returns PKCS#11 URI for specified key ID.
// It does not return key bytes
func (p *Provider) ExportKey(keyID string) (string, []byte, error) {
	ctx := context.Background()
	resp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return "", nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}

	uri := fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;id=%s;serial=%s;type=private",
		p.Manufacturer(),
		p.Model(),
		keyID,
		aws.ToString(resp.KeyMetadata.Arn),
	)

	return uri, []byte(uri), nil
}

// FindKeyPairOnSlot retrieves a previously created asymmetric key, using a specified slot.
func (p *Provider) FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error) {
	return nil, errors.Errorf("unsupported command for this crypto provider")
}

// Close allocated resources and file reloader
func (p *Provider) Close() error {
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

// Ensure compiles
var _ cryptoprov.Provider = (*Provider)(nil)
var _ cryptoprov.KeyManager = (*Provider)(nil)
