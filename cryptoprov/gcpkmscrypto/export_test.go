package gcpkmscrypto

import (
	"context"
	"time"

	"github.com/effective-security/xpki/cryptoprov"
)

// NewTestProvider returns a provider for keyring that uses client, without
// the process-global KmsClientFactory, so tests can run in parallel.
func NewTestProvider(tc cryptoprov.TokenConfig, client KmsClient, keyring string) *Provider {
	return newProvider(tc, client, "", keyring)
}

// SetGenerationWait configures the wait for key generation: at most attempts
// polls, interval apart. sleep, when not nil, replaces the wait between
// polls.
func SetGenerationWait(p *Provider, interval time.Duration, attempts int, sleep func(context.Context, time.Duration) error) {
	p.pollInterval = interval
	p.pollAttempts = attempts
	p.sleep = sleep
}

// GenKey is genKey, so tests can cancel its context.
var GenKey = (*Provider).genKey

// NewKmsClient is the SDK client construction path of the default
// KmsClientFactory.
var NewKmsClient = newKmsClient
