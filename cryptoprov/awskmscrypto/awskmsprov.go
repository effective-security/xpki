package awskmscrypto

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/metricskey"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "awskmscrypto")

// ProviderName specifies a provider name
const ProviderName = "AWSKMS"

const (
	// attrEndpoint and attrRegion are the token config Attributes.
	attrEndpoint = "Endpoint"
	attrRegion   = "Region"

	// purposeEncryption is the GenerateRSAKey purpose of an encryption key,
	// which this provider does not support (XPKI-031).
	purposeEncryption = 2

	// listKeysLimit is the ListKeys page size, the KMS maximum.
	listKeysLimit = 1000
	// describeConcurrency is how many DescribeKey calls EnumKeys has in
	// flight at once (XPKI-032). DescribeKey shares the KMS request quota
	// with the other management operations, so it is kept small.
	describeConcurrency = 8

	aliasPrefix         = "alias/"
	reservedAliasPrefix = "aws/"

	// accessDeniedCode is the code of the KMS access denied error, which is
	// not modelled in the KMS types.
	accessDeniedCode = "AccessDeniedException"
)

// errEmptyResponse is the cause of an error for a nil KMS response.
var errEmptyResponse = errors.New("empty response")

// rsaKeySpecs maps the RSA key sizes KMS supports to their key spec.
var rsaKeySpecs = map[int]types.KeySpec{
	2048: types.KeySpecRsa2048,
	3072: types.KeySpecRsa3072,
	4096: types.KeySpecRsa4096,
}

func init() {
	_ = cryptoprov.Register(ProviderName, KmsLoader)
}

// KmsClient interface
type KmsClient interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(context.Context, *kms.CreateAliasInput, ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KmsClientFactory creates the KMS client for Init; tests override it.
var KmsClientFactory = func(cfg aws.Config, optFns ...func(*kms.Options)) KmsClient {
	return kms.NewFromConfig(cfg, optFns...)
}

// Provider implements Provider interface for KMS
type Provider struct {
	tc        cryptoprov.TokenConfig
	kmsClient KmsClient
	endpoint  string
	region    string

	// describeConcurrency is the number of DescribeKey calls EnumKeys has in
	// flight at once.
	describeConcurrency int
}

// Init creates a provider for tc, whose Attributes may carry
// "Endpoint=<url>" and "Region=<region>". Credentials, the default region
// and retries come from the default AWS SDK chain, which reads
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN before the
// shared config, so the provider does not copy them into a static
// provider of its own (XPKI-034). The client from KmsClientFactory makes no
// request until a key operation.
func Init(tc cryptoprov.TokenConfig) (*Provider, error) {
	kmsAttributes := parseKmsAttributes(tc.Attributes())
	endpoint := kmsAttributes[attrEndpoint]
	region := kmsAttributes[attrRegion]

	var awsops []func(*awsconfig.LoadOptions) error
	if region != "" {
		awsops = append(awsops, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsops...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load AWS configuration")
	}

	var kmsops []func(*kms.Options)
	if endpoint != "" {
		// Use service-specific endpoint resolution via BaseEndpoint.
		// https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/endpoints/
		kmsops = append(kmsops, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	client := KmsClientFactory(cfg, kmsops...)
	if client == nil {
		return nil, errors.New("KMS client factory returned no client")
	}
	return newProvider(tc, client, endpoint, region), nil
}

// newProvider returns a provider over client.
func newProvider(tc cryptoprov.TokenConfig, client KmsClient, endpoint, region string) *Provider {
	return &Provider{
		tc:                  tc,
		kmsClient:           client,
		endpoint:            endpoint,
		region:              region,
		describeConcurrency: describeConcurrency,
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

// GenerateRSAKey creates a KMS signing key of bits (2048, 3072 or 4096) with
// label as its description and alias, and returns its Signer. This provider
// has no decrypter, so the encryption purpose (2) is an error before any
// RPC (XPKI-031); any other purpose is a signing key.
func (p *Provider) GenerateRSAKey(label string, bits int, purpose int) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_rsa")

	if purpose == purposeEncryption {
		return nil, errors.Errorf("unsupported key purpose: %d, only signing keys are supported", purpose)
	}
	spec, ok := rsaKeySpecs[bits]
	if !ok {
		return nil, errors.Errorf("unsupported RSA key size: %d", bits)
	}
	return p.createSigningKey(context.Background(), label, spec)
}

// GenerateECDSAKey creates a KMS signing key on curve (P-256, P-384 or
// P-521) with label as its description and alias, and returns its Signer.
func (p *Provider) GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "genkey_ecdsa")

	var spec types.KeySpec
	switch curve {
	case elliptic.P256():
		spec = types.KeySpecEccNistP256
	case elliptic.P384():
		spec = types.KeySpecEccNistP384
	case elliptic.P521():
		spec = types.KeySpecEccNistP521
	default:
		return nil, errors.New("unsupported curve")
	}
	return p.createSigningKey(context.Background(), label, spec)
}

// createSigningKey creates a SIGN_VERIFY key of spec described by label,
// gives it the alias of label when label is not empty, and returns its
// Signer. An alias failure is logged: the key exists and is usable without
// it. When the public key can not be fetched, the key is scheduled for
// deletion, so no unusable key is left behind.
func (p *Provider) createSigningKey(ctx context.Context, label string, spec types.KeySpec) (crypto.PrivateKey, error) {
	input := &kms.CreateKeyInput{
		KeySpec:     spec,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(label),
	}
	resp, err := p.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create key with label: %q", label)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return nil, errors.Wrapf(errEmptyResponse, "failed to create key with label: %q", label)
	}

	keyID := aws.ToString(resp.KeyMetadata.KeyId)
	arn := aws.ToString(resp.KeyMetadata.Arn)
	logger.KV(xlog.INFO, "arn", arn, "id", keyID, "label", label)

	if label != "" {
		if _, err := p.createAlias(ctx, keyID, label); err != nil {
			logger.KV(xlog.WARNING, "reason", "CreateAlias", "id", keyID, "err", err.Error())
		}
	}

	signer, err := p.signer(ctx, keyID, label)
	if err != nil {
		p.discardKey(ctx, keyID)
		return nil, err
	}
	return signer, nil
}

// discardKey schedules the deletion of a key whose creation did not
// complete. A failure is logged: the caller gets the creation error.
func (p *Provider) discardKey(ctx context.Context, keyID string) {
	_, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		logger.KV(xlog.WARNING, "reason", "ScheduleKeyDeletion", "id", keyID, "err", err.Error())
		return
	}
	logger.KV(xlog.WARNING, "reason", "incomplete key scheduled for deletion", "id", keyID)
}

// signer fetches the public key of keyID and returns its Signer with the
// signing algorithms KMS reports for the key.
func (p *Provider) signer(ctx context.Context, keyID, label string) (crypto.PrivateKey, error) {
	resp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
	}
	pub, err := parsePublicKey(resp)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
	}
	return NewSigner(keyID, label, resp.SigningAlgorithms, pub, p.kmsClient), nil
}

// parsePublicKey parses the PKIX public key of a GetPublicKey response.
func parsePublicKey(resp *kms.GetPublicKeyOutput) (crypto.PublicKey, error) {
	if resp == nil || len(resp.PublicKey) == 0 {
		return nil, errors.WithStack(errEmptyResponse)
	}
	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return pub, nil
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
	name := strings.TrimPrefix(strings.Map(replace, label), reservedAliasPrefix)
	return aliasPrefix + name
}

// createAlias creates a KMS alias for the given key using the provided label.
// The key already exists at this point, so an alias failure is logged as a
// warning and treated as non-fatal. It returns the alias name that was used.
func (p *Provider) createAlias(ctx context.Context, keyID, label string) (string, error) {
	alias := aliasFromLabel(label)
	if alias == aliasPrefix {
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

// GetKey returns the Signer of the KMS key keyID (a key id, ARN, alias name
// or alias ARN), labelled with the key description. The key usage must be
// SIGN_VERIFY and the key must not be pending deletion: neither can sign,
// so no signer is returned for them (XPKI-031). A disabled key gets a
// signer, since it can be enabled again; its Sign fails until then.
func (p *Provider) GetKey(keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	ctx := context.Background()
	logger.KV(xlog.INFO, "api", "GetKey", "keyID", keyID)

	meta, err := p.describeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if meta.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, errors.Errorf("key %s usage %s is not valid for signing", keyID, meta.KeyUsage)
	}
	if meta.KeyState == types.KeyStatePendingDeletion {
		return nil, errors.Errorf("key %s is pending deletion", keyID)
	}
	return p.signer(ctx, keyID, aws.ToString(meta.Description))
}

// describeKey returns the metadata of the key keyID.
func (p *Provider) describeKey(ctx context.Context, keyID string) (*types.KeyMetadata, error) {
	resp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s", keyID)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return nil, errors.Wrapf(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}
	return resp.KeyMetadata, nil
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

func keyMeta(meta *types.KeyMetadata) map[string]string {
	return map[string]string{
		"description": aws.ToString(meta.Description),
		"usage":       string(meta.KeyUsage),
		"origin":      string(meta.Origin),
		"state":       string(meta.KeyState),
		"enabled":     fmt.Sprintf("%t", meta.Enabled),
		"algo":        fmt.Sprintf("%v", meta.SigningAlgorithms),
	}
}

// EnumKeys lists the signing keys (usage SIGN_VERIFY, not pending deletion)
// whose label, the KMS key description, starts with prefix; an empty prefix
// lists all of them. slotID is ignored. KMS lists key ids only, so every
// key of the account is described (XPKI-032), describeConcurrency calls at
// a time, with the SDK retrying throttled calls; the caller needs
// kms:ListKeys and kms:DescribeKey. A key the caller may not describe
// (AccessDeniedException) is not listed and is logged. Any other ListKeys
// or DescribeKey failure ends the listing and is returned wrapped, so
// errors.As still finds the service error; there is no partial result
// (XPKI-033). Keys are returned in the KMS listing order.
func (p *Provider) EnumKeys(slotID uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "enumkeys")
	logger.KV(xlog.DEBUG, "endpoint", p.endpoint, "slotID", slotID, "prefix", prefix)

	ctx := context.Background()
	input := &kms.ListKeysInput{
		Limit: aws.Int32(listKeysLimit),
	}

	totalKeys := 0
	res := make([]cryptoprov.KeyInfo, 0)
	for pageNumber := 1; ; pageNumber++ {
		page, err := p.kmsClient.ListKeys(ctx, input)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to list keys")
		}
		if page == nil {
			return nil, errors.Wrap(errEmptyResponse, "failed to list keys")
		}

		totalKeys += len(page.Keys)
		keys, err := p.describeKeys(ctx, page.Keys, prefix)
		if err != nil {
			return nil, err
		}
		res = append(res, keys...)

		if !page.Truncated {
			break
		}
		if page.NextMarker == nil {
			return nil, errors.Errorf("failed to list keys: page %d is truncated without a marker", pageNumber)
		}
		input.Marker = page.NextMarker
	}
	logger.KV(xlog.DEBUG, "total_keys", totalKeys, "sign_keys", len(res))

	return res, nil
}

// describeKeys describes keys, p.describeConcurrency at a time, and returns
// in listing order the signing keys whose label starts with prefix. The
// first failure cancels the calls in flight and is returned.
func (p *Provider) describeKeys(ctx context.Context, keys []types.KeyListEntry, prefix string) ([]cryptoprov.KeyInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		once.Do(func() {
			firstErr = err
			cancel()
		})
	}

	infos := make([]*cryptoprov.KeyInfo, len(keys))
	sem := make(chan struct{}, max(p.describeConcurrency, 1))
	for i, key := range keys {
		sem <- struct{}{}
		if ctx.Err() != nil {
			// a describe failed while waiting for a slot
			<-sem
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			info, err := p.listedKey(ctx, key, prefix)
			if err != nil {
				fail(err)
				return
			}
			infos[i] = info
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	res := make([]cryptoprov.KeyInfo, 0, len(keys))
	for _, info := range infos {
		if info != nil {
			res = append(res, *info)
		}
	}
	return res, nil
}

// listedKey describes key and returns its KeyInfo, or nil when it is not
// listed: not a signing key, pending deletion, a label without prefix, or
// not describable by the caller.
func (p *Provider) listedKey(ctx context.Context, key types.KeyListEntry, prefix string) (*cryptoprov.KeyInfo, error) {
	keyID := aws.ToString(key.KeyId)
	arn := aws.ToString(key.KeyArn)
	resp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
	if err != nil {
		if isAccessDenied(err) {
			logger.KV(xlog.WARNING, "reason", "DescribeKey", "id", keyID, "arn", arn, "err", err.Error())
			return nil, nil
		}
		return nil, errors.WithMessagef(err, "failed to describe key, id=%s, arn=%s", keyID, arn)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return nil, errors.Wrapf(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}
	meta := resp.KeyMetadata
	if meta.KeyUsage != types.KeyUsageTypeSignVerify || meta.KeyState == types.KeyStatePendingDeletion {
		return nil, nil
	}
	label := aws.ToString(meta.Description)
	if !strings.HasPrefix(label, prefix) {
		return nil, nil
	}
	return &cryptoprov.KeyInfo{
		ID:           keyID,
		Label:        label,
		Meta:         keyMeta(meta),
		CreationTime: meta.CreationDate,
	}, nil
}

// isAccessDenied reports whether err is the KMS AccessDeniedException.
func isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == accessDeniedCode
}

// DestroyKeyPairOnSlot destroys key pair on slot. For KMS slotID is ignored and KMS retire API is used to destroy the key.
func (p *Provider) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	ctx := context.Background()
	resp, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return errors.WithMessagef(err, "failed to schedule key deletion: %s", keyID)
	}
	if resp == nil {
		return errors.Wrapf(errEmptyResponse, "failed to schedule key deletion: %s", keyID)
	}
	logger.KV(xlog.NOTICE, "id", keyID, "deletion_time", aws.ToTime(resp.DeletionDate).Format(time.RFC3339))

	return nil
}

// KeyInfo retrieves info about key with the specified id
func (p *Provider) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	ctx := context.Background()
	meta, err := p.describeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	pubKey := ""
	if includePublic {
		resp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to get public key, id=%s", keyID)
		}
		pub, err := parsePublicKey(resp)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
		}
		pemKey, err := certutil.EncodePublicKeyToPEM(pub)
		if err != nil {
			return nil, err
		}
		pubKey = string(pemKey)
	}

	return &cryptoprov.KeyInfo{
		ID:           keyID,
		Label:        aws.ToString(meta.Description),
		PublicKey:    pubKey,
		Meta:         keyMeta(meta),
		CreationTime: meta.CreationDate,
	}, nil
}

// ExportKey returns PKCS#11 URI for specified key ID.
// It does not return key bytes
func (p *Provider) ExportKey(keyID string) (string, []byte, error) {
	meta, err := p.describeKey(context.Background(), keyID)
	if err != nil {
		return "", nil, err
	}

	uri := fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;id=%s;serial=%s;type=private",
		p.Manufacturer(),
		p.Model(),
		keyID,
		aws.ToString(meta.Arn),
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
