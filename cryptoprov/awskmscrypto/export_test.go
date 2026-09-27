package awskmscrypto

import "github.com/effective-security/xpki/cryptoprov"

// Package constants exposed to the black-box tests.
const (
	DescribeConcurrency = describeConcurrency
	ListKeysLimit       = listKeysLimit
)

// NewTestProvider returns a provider for tc over client, without the
// process-global KmsClientFactory, so tests can run in parallel.
func NewTestProvider(tc cryptoprov.TokenConfig, client KmsClient) *Provider {
	return newProvider(tc, client, "", "")
}

// SetDescribeConcurrency sets how many DescribeKey calls EnumKeys of p has
// in flight at once.
func SetDescribeConcurrency(p *Provider, n int) {
	p.describeConcurrency = n
}

// Client returns the KMS client of p.
func Client(p *Provider) KmsClient {
	return p.kmsClient
}

// ParseKmsAttributes is parseKmsAttributes.
var ParseKmsAttributes = parseKmsAttributes

// AliasFromLabel is aliasFromLabel.
var AliasFromLabel = aliasFromLabel
