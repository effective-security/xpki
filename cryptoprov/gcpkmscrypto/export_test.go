package gcpkmscrypto

// NewTestProvider returns a provider for keyring that uses client, without
// the process-global KmsClientFactory, so tests can run in parallel.
func NewTestProvider(client KmsClient, keyring string) *Provider {
	return &Provider{
		KmsClient: client,
		keyring:   keyring,
	}
}
