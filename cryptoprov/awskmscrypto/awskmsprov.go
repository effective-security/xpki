package awskmscrypto

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/metricskey"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "awskmscrypto")

// ProviderName specifies a provider name
const ProviderName = "AWSKMS"

// The token config Attributes of the provider, "Name=value" pairs separated
// by commas.
const (
	// attrEndpoint is the KMS endpoint URL, for an emulator or a VPC
	// endpoint, and attrRegion the AWS Region.
	attrEndpoint = "Endpoint"
	attrRegion   = "Region"
	// attrTagSearch, "true" or "false", turns the Resource Groups Tagging
	// API on: a tag filter is answered by GetResources, GenerateKey writes
	// the xpki tags, and the xpki-label tag is a second label index. It
	// needs tag:GetResources and kms:TagResource. attrTaggingEndpoint is the
	// endpoint URL of that API.
	attrTagSearch       = "TagSearch"
	attrTaggingEndpoint = "TaggingEndpoint"
	// attrLabelSearch selects how a label filter finds keys:
	// labelSearchIndex (the default) through the alias of the label,
	// labelSearchScan by describing every key of the account and matching
	// its description.
	attrLabelSearch = "LabelSearch"
	// attrDescribeConcurrency is the number of per-key requests a listing
	// has in flight at once, 1 to maxDescribeConcurrency.
	attrDescribeConcurrency = "DescribeConcurrency"
	// attrMetadataCacheSize is the number of keys whose immutable metadata
	// the provider remembers; 0 disables the cache.
	attrMetadataCacheSize = "MetadataCacheSize"

	labelSearchIndex = "index"
	labelSearchScan  = "scan"
)

const (
	// listKeysLimit is the ListKeys page size, the KMS maximum,
	// listAliasesLimit the ListAliases one and resourcesPerPage the
	// GetResources one.
	listKeysLimit    = 1000
	listAliasesLimit = 100
	resourcesPerPage = 100
	// describeConcurrency is how many per-key requests (DescribeKey,
	// ListResourceTags) a listing has in flight at once by default
	// (XPKI-032). They share the KMS request quota with the other management
	// operations, so it is kept small.
	describeConcurrency    = 8
	maxDescribeConcurrency = 64
	// defaultMetadataCacheSize is the default bound of the immutable
	// metadata cache, in keys.
	defaultMetadataCacheSize = 50000

	aliasPrefix         = "alias/"
	reservedAliasPrefix = "aws/"

	// accessDeniedCode is the code of the KMS access denied error, which is
	// not modelled in the KMS types.
	accessDeniedCode = "AccessDeniedException"

	// kmsKeyResourceType is the Resource Groups Tagging API resource type of
	// a KMS key, and keyArnResource what precedes the key id in a key ARN.
	kmsKeyResourceType = "kms:key"
	keyArnResource     = ":key/"

	// The tags GenerateKey writes with TagSearch, so that a listing from the
	// tagging API needs no DescribeKey: the label, the cryptoprov key type,
	// its size and its usage. reservedTagPrefix is the prefix a caller's
	// own tags must not use.
	reservedTagPrefix = "xpki-"
	tagLabel          = reservedTagPrefix + "label"
	tagType           = reservedTagPrefix + "type"
	tagSize           = reservedTagPrefix + "size"
	tagUsage          = reservedTagPrefix + "usage"

	// maxTagValueLength is the KMS limit on a tag value, in characters, and
	// tagValuePunctuation the characters it may have besides letters, digits
	// and spaces.
	maxTagValueLength   = 256
	tagValuePunctuation = "_.:/=+-@"

	// Names of the KeyInfo.Meta entries.
	metaDescription = "description"
	metaUsage       = "usage"
	metaOrigin      = "origin"
	metaManager     = "manager"
	metaSpec        = "spec"
	metaState       = "state"
	metaEnabled     = "enabled"
	metaAlgo        = "algo"

	// Metric actions of GenerateKey by key type.
	actionGenRSA   = "genkey_rsa"
	actionGenECDSA = "genkey_ecdsa"
	actionGenMLDSA = "genkey_mldsa"
)

// errEmptyResponse is the cause of an error for a nil KMS response.
var errEmptyResponse = errors.New("empty response")

// keySpecInfo is the cryptoprov type and size of a KMS key spec.
type keySpecInfo struct {
	keyType string
	size    int
}

// keySpecs maps the key specs of the key families this module uses to their
// cryptoprov type and size. A spec that is not here (symmetric, HMAC, SM2,
// secp256k1) has an empty KeyInfo.Type.
var keySpecs = map[types.KeySpec]keySpecInfo{
	types.KeySpecRsa2048: {
		keyType: certutil.KeyTypeRSA,
		size:    2048,
	},
	types.KeySpecRsa3072: {
		keyType: certutil.KeyTypeRSA,
		size:    3072,
	},
	types.KeySpecRsa4096: {
		keyType: certutil.KeyTypeRSA,
		size:    4096,
	},
	types.KeySpecEccNistP256: {
		keyType: certutil.KeyTypeECDSA,
		size:    256,
	},
	types.KeySpecEccNistP384: {
		keyType: certutil.KeyTypeECDSA,
		size:    384,
	},
	types.KeySpecEccNistP521: {
		keyType: certutil.KeyTypeECDSA,
		size:    521,
	},
	types.KeySpecMlDsa44: {
		keyType: certutil.KeyTypeMLDSA,
		size:    cryptoprov.MLDSA44,
	},
	types.KeySpecMlDsa65: {
		keyType: certutil.KeyTypeMLDSA,
		size:    cryptoprov.MLDSA65,
	},
	types.KeySpecMlDsa87: {
		keyType: certutil.KeyTypeMLDSA,
		size:    cryptoprov.MLDSA87,
	},
}

// keySpecFor returns the KMS key spec of a cryptoprov key type and size, or
// a wrapped cryptoprov.ErrNotSupported for a size KMS does not offer.
func keySpecFor(keyType string, size int) (types.KeySpec, error) {
	for spec, info := range keySpecs {
		if info.keyType == keyType && info.size == size {
			return spec, nil
		}
	}
	return "", errors.Wrapf(cryptoprov.ErrNotSupported, "unsupported %s key size: %d", keyType, size)
}

// mldsaParameterSet returns the parameter set name of an ML-DSA key spec,
// for example "ML-DSA-65", and "" for any other spec.
func mldsaParameterSet(spec types.KeySpec) string {
	info, ok := keySpecs[spec]
	if !ok || info.keyType != certutil.KeyTypeMLDSA {
		return ""
	}
	params, err := cryptoprov.MLDSAParameters(info.size)
	if err != nil {
		return ""
	}
	return params.String()
}

// keyUsage returns the cryptoprov usage of a KMS key usage, and zero for a
// usage other than signing and encryption.
func keyUsage(usage types.KeyUsageType) cryptoprov.KeyUsage {
	switch usage {
	case types.KeyUsageTypeSignVerify:
		return cryptoprov.KeyUsageSign
	case types.KeyUsageTypeEncryptDecrypt:
		return cryptoprov.KeyUsageEncrypt
	default:
		return 0
	}
}

// keyState returns the cryptoprov state of a KMS key state. A key that is
// being updated keeps working, so it is enabled.
func keyState(state types.KeyState) cryptoprov.KeyState {
	switch state {
	case types.KeyStateEnabled, types.KeyStateUpdating:
		return cryptoprov.KeyStateEnabled
	case types.KeyStateDisabled:
		return cryptoprov.KeyStateDisabled
	case types.KeyStatePendingDeletion, types.KeyStatePendingReplicaDeletion:
		return cryptoprov.KeyStatePendingDeletion
	default:
		return cryptoprov.KeyStateUnavailable
	}
}

func init() {
	_ = cryptoprov.Register(ProviderName, KmsLoader)
}

// KmsClient is the subset of the KMS client the provider uses.
type KmsClient interface {
	CreateKey(context.Context, *kms.CreateKeyInput, ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(context.Context, *kms.CreateAliasInput, ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	ListAliases(context.Context, *kms.ListAliasesInput, ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// TaggingClient is the subset of the Resource Groups Tagging API client the
// provider uses when the TagSearch attribute is on.
type TaggingClient interface {
	GetResources(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}

// KmsClientFactory creates the KMS client for Init; tests override it.
var KmsClientFactory = func(cfg aws.Config, optFns ...func(*kms.Options)) KmsClient {
	return kms.NewFromConfig(cfg, optFns...)
}

// TaggingClientFactory creates the Resource Groups Tagging API client for
// Init when the TagSearch attribute is on; tests override it.
var TaggingClientFactory = func(cfg aws.Config, optFns ...func(*resourcegroupstaggingapi.Options)) TaggingClient {
	return resourcegroupstaggingapi.NewFromConfig(cfg, optFns...)
}

// options are the provider settings of the token config Attributes.
type options struct {
	endpoint            string
	region              string
	taggingEndpoint     string
	tagSearch           bool
	labelScan           bool
	describeConcurrency int
	metadataCacheSize   int
}

// parseOptions reads the provider settings from the token config Attributes
// and rejects a value it does not understand, so a mistyped setting fails
// Init instead of being ignored.
func parseOptions(attributes string) (*options, error) {
	attrs := parseKmsAttributes(attributes)
	opts := &options{
		endpoint:            attrs[attrEndpoint],
		region:              attrs[attrRegion],
		taggingEndpoint:     attrs[attrTaggingEndpoint],
		describeConcurrency: describeConcurrency,
		metadataCacheSize:   defaultMetadataCacheSize,
	}

	var err error
	if v, ok := attrs[attrTagSearch]; ok {
		if opts.tagSearch, err = strconv.ParseBool(v); err != nil {
			return nil, errors.Errorf("invalid %s attribute %q: expected true or false", attrTagSearch, v)
		}
	}
	switch v := attrs[attrLabelSearch]; v {
	case "", labelSearchIndex:
	case labelSearchScan:
		opts.labelScan = true
	default:
		return nil, errors.Errorf("invalid %s attribute %q: expected %s or %s", attrLabelSearch, v, labelSearchIndex, labelSearchScan)
	}
	if v, ok := attrs[attrDescribeConcurrency]; ok {
		opts.describeConcurrency, err = strconv.Atoi(v)
		if err != nil || opts.describeConcurrency < 1 || opts.describeConcurrency > maxDescribeConcurrency {
			return nil, errors.Errorf("invalid %s attribute %q: expected 1 to %d", attrDescribeConcurrency, v, maxDescribeConcurrency)
		}
	}
	if v, ok := attrs[attrMetadataCacheSize]; ok {
		opts.metadataCacheSize, err = strconv.Atoi(v)
		if err != nil || opts.metadataCacheSize < 0 {
			return nil, errors.Errorf("invalid %s attribute %q: expected 0 or more", attrMetadataCacheSize, v)
		}
	}
	return opts, nil
}

// Provider implements cryptoprov.Provider and cryptoprov.KeyManager for AWS
// KMS: the keys of one account and Region. It is safe for concurrent use.
type Provider struct {
	tc        cryptoprov.TokenConfig
	kmsClient KmsClient
	// tagClient is nil unless the TagSearch attribute is on.
	tagClient TaggingClient
	endpoint  string
	region    string

	// labelScan makes a label filter describe every key instead of looking
	// the label up through its alias (the LabelSearch=scan attribute).
	labelScan bool
	// describeConcurrency is the number of per-key requests a listing has
	// in flight at once.
	describeConcurrency int
	// metaCache has the immutable metadata of the keys described so far;
	// nil when the cache is disabled.
	metaCache *metadataCache
}

// Init creates a provider for tc. Its Attributes may carry "Endpoint=<url>"
// and "Region=<region>", and the listing settings "TagSearch=true" (with
// "TaggingEndpoint=<url>"), "LabelSearch=scan", "DescribeConcurrency=<n>"
// and "MetadataCacheSize=<n>", which ListKeys describes; an invalid value
// is an error. Credentials, the default region and retries come from the
// default AWS SDK chain, which reads AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN before the shared config, so
// the provider does not copy them into a static provider of its own
// (XPKI-034). The clients from KmsClientFactory and TaggingClientFactory
// make no request until a key operation.
func Init(tc cryptoprov.TokenConfig) (*Provider, error) {
	opts, err := parseOptions(tc.Attributes())
	if err != nil {
		return nil, err
	}

	var awsops []func(*awsconfig.LoadOptions) error
	if opts.region != "" {
		awsops = append(awsops, awsconfig.WithRegion(opts.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsops...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load AWS configuration")
	}

	var kmsops []func(*kms.Options)
	if opts.endpoint != "" {
		// Use service-specific endpoint resolution via BaseEndpoint.
		// https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/endpoints/
		kmsops = append(kmsops, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(opts.endpoint)
		})
	}

	client := KmsClientFactory(cfg, kmsops...)
	if client == nil {
		return nil, errors.New("KMS client factory returned no client")
	}

	var tagClient TaggingClient
	if opts.tagSearch {
		var tagops []func(*resourcegroupstaggingapi.Options)
		if opts.taggingEndpoint != "" {
			tagops = append(tagops, func(o *resourcegroupstaggingapi.Options) {
				o.BaseEndpoint = aws.String(opts.taggingEndpoint)
			})
		}
		if tagClient = TaggingClientFactory(cfg, tagops...); tagClient == nil {
			return nil, errors.New("tagging client factory returned no client")
		}
	}
	return newProvider(tc, client, tagClient, opts), nil
}

// newProvider returns a provider over client, and over tagClient when it is
// not nil.
func newProvider(tc cryptoprov.TokenConfig, client KmsClient, tagClient TaggingClient, opts *options) *Provider {
	return &Provider{
		tc:                  tc,
		kmsClient:           client,
		tagClient:           tagClient,
		endpoint:            opts.endpoint,
		region:              opts.region,
		labelScan:           opts.labelScan,
		describeConcurrency: opts.describeConcurrency,
		metaCache:           newMetadataCache(opts.metadataCacheSize),
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

// tagSearch reports whether the Resource Groups Tagging API is on.
func (p *Provider) tagSearch() bool {
	return p.tagClient != nil
}

// GenerateKey creates a KMS signing key as req describes it: RSA of 2048,
// 3072 or 4096 bits, ECDSA on P-256, P-384 or P-521, or ML-DSA-44, 65 or 87
// (key spec ML_DSA_*), with req.Label as its description and alias and
// req.Tags as its tags, and returns its Signer. With the TagSearch
// attribute it also writes the xpki-label, xpki-type, xpki-size and
// xpki-usage tags that let a listing skip DescribeKey; tags need
// kms:TagResource, and a tag name that starts with "xpki-" is reserved.
//
// An ML-DSA signer signs messages through the EXTERNAL_MU operation: μ is
// computed locally, so the message never leaves the process and the RAW
// message size limit of KMS does not apply; see
// cryptoprov.MLDSASignerOptions for the options it accepts. This provider
// has no decrypter, so cryptoprov.KeyUsageEncrypt is a wrapped
// cryptoprov.ErrNotSupported before any request (XPKI-031), as is a size
// KMS does not offer.
func (p *Provider) GenerateKey(ctx context.Context, req *cryptoprov.GenerateKeyRequest) (crypto.PrivateKey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	action := actionGenRSA
	switch req.Type {
	case certutil.KeyTypeECDSA:
		action = actionGenECDSA
	case certutil.KeyTypeMLDSA:
		action = actionGenMLDSA
	}
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, action)

	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	usage := req.KeyUsage()
	if usage != cryptoprov.KeyUsageSign {
		return nil, errors.Wrapf(cryptoprov.ErrNotSupported, "unsupported key usage: %s, only signing keys are supported", usage)
	}
	spec, err := keySpecFor(req.Type, req.Size)
	if err != nil {
		return nil, err
	}
	tags, err := p.keyTags(req)
	if err != nil {
		return nil, err
	}
	return p.createSigningKey(ctx, req.Label, spec, tags)
}

// keyTags returns the tags of the key req creates: the caller's, in name
// order, and with TagSearch the xpki tags. The label tag is left out for a
// label that is empty or not a valid tag value; such a key is found through
// its alias only.
func (p *Provider) keyTags(req *cryptoprov.GenerateKeyRequest) ([]types.Tag, error) {
	tags := make([]types.Tag, 0, len(req.Tags)+4)
	for _, name := range slices.Sorted(maps.Keys(req.Tags)) {
		if strings.HasPrefix(name, reservedTagPrefix) {
			return nil, errors.Errorf("invalid tag %q: the %q prefix is reserved", name, reservedTagPrefix)
		}
		tags = append(tags, types.Tag{
			TagKey:   aws.String(name),
			TagValue: aws.String(req.Tags[name]),
		})
	}
	if !p.tagSearch() {
		return tags, nil
	}
	if req.Label != "" && validTagValue(req.Label) {
		tags = append(tags, types.Tag{
			TagKey:   aws.String(tagLabel),
			TagValue: aws.String(req.Label),
		})
	}
	return append(tags,
		types.Tag{
			TagKey:   aws.String(tagType),
			TagValue: aws.String(req.Type),
		},
		types.Tag{
			TagKey:   aws.String(tagSize),
			TagValue: aws.String(strconv.Itoa(req.Size)),
		},
		types.Tag{
			TagKey:   aws.String(tagUsage),
			TagValue: aws.String(req.KeyUsage().String()),
		},
	), nil
}

// validTagValue reports whether KMS accepts s as a tag value: at most
// maxTagValueLength letters, digits, spaces and tagValuePunctuation.
func validTagValue(s string) bool {
	if utf8.RuneCountInString(s) > maxTagValueLength {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune(tagValuePunctuation, r) {
			return false
		}
	}
	return true
}

// createSigningKey creates a SIGN_VERIFY key of spec described by label with
// tags, gives it the alias of label when label is not empty, and returns its
// Signer. An alias failure is logged: the key exists and is usable without
// it, but a label filter finds it only through the xpki-label tag or with
// LabelSearch=scan. When the public key can not be fetched, the key is
// scheduled for deletion, so no unusable key is left behind.
func (p *Provider) createSigningKey(ctx context.Context, label string, spec types.KeySpec, tags []types.Tag) (crypto.PrivateKey, error) {
	input := &kms.CreateKeyInput{
		KeySpec:     spec,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(label),
	}
	if len(tags) > 0 {
		input.Tags = tags
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
// complete. A failure is logged: the caller gets the creation error. The
// caller's context may be why the creation failed, so the request does not
// inherit its cancellation.
func (p *Provider) discardKey(ctx context.Context, keyID string) {
	_, err := p.kmsClient.ScheduleKeyDeletion(context.WithoutCancel(ctx), &kms.ScheduleKeyDeletionInput{
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
		return nil, kmsError(err, "failed to get public key, id=%s", keyID)
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

// IdentifyKey returns key id and label for the given private key. It makes
// no request.
func (p *Provider) IdentifyKey(_ context.Context, priv crypto.PrivateKey) (keyID, label string, err error) {
	if s, ok := priv.(*Signer); ok {
		return s.KeyID(), s.Label(), nil
	}
	return "", "", errors.New("not supported key")
}

// GetKey returns the Signer of the KMS key keyID (a key id, ARN, alias name
// or alias ARN), labelled with the key description. The key usage must be
// SIGN_VERIFY, otherwise the error wraps cryptoprov.ErrNotSupported, and the
// key must not be pending deletion: neither can sign, so no signer is
// returned for them (XPKI-031). A disabled key gets a signer, since it can
// be enabled again; its Sign fails until then. A key KMS does not have is a
// wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "getkey")

	logger.KV(xlog.INFO, "api", "GetKey", "keyID", keyID)

	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	meta, err := p.describeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if meta.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, errors.Wrapf(cryptoprov.ErrNotSupported, "key %s usage %s is not valid for signing", keyID, meta.KeyUsage)
	}
	if meta.KeyState == types.KeyStatePendingDeletion {
		return nil, errors.Errorf("key %s is pending deletion", keyID)
	}
	return p.signer(ctx, keyID, aws.ToString(meta.Description))
}

// describeKey returns the metadata of the key keyID, a key id, ARN or alias,
// and remembers its immutable part. A key KMS does not have is a wrapped
// cryptoprov.ErrKeyNotFound.
func (p *Provider) describeKey(ctx context.Context, keyID string) (*types.KeyMetadata, error) {
	resp, err := p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, kmsError(err, "failed to describe key, id=%s", keyID)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return nil, errors.Wrapf(errEmptyResponse, "failed to describe key, id=%s", keyID)
	}
	p.metaCache.put(aws.ToString(resp.KeyMetadata.KeyId), immutableOf(resp.KeyMetadata))
	return resp.KeyMetadata, nil
}

// kmsError wraps a KMS error with a message, and marks a NotFoundException
// as cryptoprov.ErrKeyNotFound. errors.As still finds the service error.
func kmsError(err error, format string, args ...any) error {
	wrapped := errors.WithMessagef(err, format, args...)
	var notFound *types.NotFoundException
	if errors.As(err, &notFound) {
		return cryptoprov.MarkError(wrapped, cryptoprov.ErrKeyNotFound)
	}
	return wrapped
}

// isAccessDenied reports whether err is the KMS AccessDeniedException.
func isAccessDenied(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == accessDeniedCode
}

// keyMeta returns the KeyInfo.Meta of a described key; an ML-DSA key also
// reports its parameter set under cryptoprov.MetaParameterSet.
func keyMeta(meta *types.KeyMetadata) map[string]string {
	m := immutableOf(meta).meta()
	m[metaDescription] = aws.ToString(meta.Description)
	m[metaState] = string(meta.KeyState)
	m[metaEnabled] = strconv.FormatBool(meta.Enabled)
	m[metaAlgo] = fmt.Sprintf("%v", meta.SigningAlgorithms)
	return m
}

// meta returns the KeyInfo.Meta entries the immutable metadata supplies.
func (m *immutableMeta) meta() map[string]string {
	res := map[string]string{
		metaUsage:   string(m.usage),
		metaOrigin:  string(m.origin),
		metaManager: string(m.manager),
		metaSpec:    string(m.spec),
	}
	if parameterSet := mldsaParameterSet(m.spec); parameterSet != "" {
		res[cryptoprov.MetaParameterSet] = parameterSet
	}
	return res
}

// fill sets the KeyInfo fields the immutable metadata supplies: Name, Type,
// Size, Usage and CreationTime.
func (m *immutableMeta) fill(ki *cryptoprov.KeyInfo) {
	if m.arn != "" {
		ki.Name = m.arn
	}
	info := keySpecs[m.spec]
	ki.Type = info.keyType
	ki.Size = info.size
	ki.Usage = keyUsage(m.usage)
	ki.CreationTime = m.created
}

// describedKeyInfo returns the KeyInfo of a described key: every field of
// the Metadata and State groups.
func describedKeyInfo(meta *types.KeyMetadata) *cryptoprov.KeyInfo {
	ki := &cryptoprov.KeyInfo{
		ID:    aws.ToString(meta.KeyId),
		Label: aws.ToString(meta.Description),
		State: keyState(meta.KeyState),
		Meta:  keyMeta(meta),
	}
	immutableOf(meta).fill(ki)
	return ki
}

// DestroyKey schedules the deletion of the key keyID with the default KMS
// waiting period, during which the deletion can be cancelled in KMS. A key
// KMS does not have is a wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) DestroyKey(ctx context.Context, keyID string) error {
	if err := ctx.Err(); err != nil {
		return errors.WithStack(err)
	}
	resp, err := p.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return kmsError(err, "failed to schedule key deletion: %s", keyID)
	}
	if resp == nil {
		return errors.Wrapf(errEmptyResponse, "failed to schedule key deletion: %s", keyID)
	}
	logger.KV(xlog.NOTICE, "id", keyID, "deletion_time", aws.ToTime(resp.DeletionDate).Format(time.RFC3339))

	return nil
}

// KeyInfo describes the key keyID (a key id, ARN, alias name or alias ARN)
// with one DescribeKey, which supplies the Metadata and State groups whatever
// fields selects. cryptoprov.KeyFieldTags adds the tags (ListResourceTags,
// which needs kms:ListResourceTags) and cryptoprov.KeyFieldPublicKey the PEM
// public key (GetPublicKey). A key KMS does not have is a wrapped
// cryptoprov.ErrKeyNotFound.
func (p *Provider) KeyInfo(ctx context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "keyinfo")

	if err := fields.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	meta, err := p.describeKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	ki := describedKeyInfo(meta)

	if fields.Has(cryptoprov.KeyFieldTags) {
		if ki.Tags, err = p.resourceTags(ctx, ki.ID); err != nil {
			return nil, err
		}
	}
	if fields.Has(cryptoprov.KeyFieldPublicKey) {
		resp, err := p.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
		if err != nil {
			return nil, kmsError(err, "failed to get public key, id=%s", keyID)
		}
		pub, err := parsePublicKey(resp)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse public key, id=%s", keyID)
		}
		pemKey, err := certutil.EncodePublicKeyToPEM(pub)
		if err != nil {
			return nil, err
		}
		ki.PublicKey = string(pemKey)
	}
	return ki, nil
}

// resourceTags returns the tags of the key keyID, reading every page of
// ListResourceTags. A key without tags has an empty, non-nil map.
func (p *Provider) resourceTags(ctx context.Context, keyID string) (map[string]string, error) {
	tags := map[string]string{}
	input := &kms.ListResourceTagsInput{KeyId: aws.String(keyID)}
	for pageNumber := 1; ; pageNumber++ {
		page, err := p.kmsClient.ListResourceTags(ctx, input)
		if err != nil {
			return nil, kmsError(err, "failed to list tags, id=%s", keyID)
		}
		if page == nil {
			return nil, errors.Wrapf(errEmptyResponse, "failed to list tags, id=%s", keyID)
		}
		for _, tag := range page.Tags {
			tags[aws.ToString(tag.TagKey)] = aws.ToString(tag.TagValue)
		}
		if !page.Truncated {
			return tags, nil
		}
		if page.NextMarker == nil {
			return nil, errors.Errorf("failed to list tags, id=%s: page %d is truncated without a marker", keyID, pageNumber)
		}
		input.Marker = page.NextMarker
	}
}

// ExportKey returns PKCS#11 URI for specified key ID.
// It does not return key bytes
func (p *Provider) ExportKey(ctx context.Context, keyID string) (string, []byte, error) {
	meta, err := p.describeKey(ctx, keyID)
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
