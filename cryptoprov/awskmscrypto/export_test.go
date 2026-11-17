package awskmscrypto

import "github.com/effective-security/xpki/v2/cryptoprov"

// Package constants exposed to the black-box tests.
const (
	DescribeConcurrency = describeConcurrency
	ListKeysLimit       = listKeysLimit
	ListAliasesLimit    = listAliasesLimit
	ResourcesPerPage    = resourcesPerPage
	TagLabel            = tagLabel
	TagType             = tagType
	TagSize             = tagSize
	TagUsage            = tagUsage
)

// NewTestProvider returns a provider for tc over client, with the listing
// settings of tc's Attributes and without the process-global
// KmsClientFactory, so tests can run in parallel. TagSearch is off.
func NewTestProvider(tc cryptoprov.TokenConfig, client KmsClient) *Provider {
	return NewTaggingTestProvider(tc, client, nil)
}

// NewTaggingTestProvider is NewTestProvider with tagClient as the Resource
// Groups Tagging API client, which turns TagSearch on when it is not nil.
func NewTaggingTestProvider(tc cryptoprov.TokenConfig, client KmsClient, tagClient TaggingClient) *Provider {
	opts, err := parseOptions(tc.Attributes())
	if err != nil {
		panic(err)
	}
	return newProvider(tc, client, tagClient, opts)
}

// SetDescribeConcurrency sets how many per-key requests a listing of p has
// in flight at once.
func SetDescribeConcurrency(p *Provider, n int) {
	p.describeConcurrency = n
}

// MetadataCacheLen returns the number of keys in the immutable metadata
// cache of p.
func MetadataCacheLen(p *Provider) int {
	return p.metaCache.len()
}

// Client returns the KMS client of p.
func Client(p *Provider) KmsClient {
	return p.kmsClient
}

// ParseKmsAttributes is parseKmsAttributes.
var ParseKmsAttributes = parseKmsAttributes

// AliasFromLabel is aliasFromLabel.
var AliasFromLabel = aliasFromLabel
