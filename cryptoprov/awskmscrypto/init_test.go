package awskmscrypto_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests here replace the process-global KmsClientFactory and the
// environment, so they do not run in parallel.

// isolateAWSEnv points the SDK at empty shared config files and clears the
// credential and region variables, so only what a test sets is seen.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	for _, name := range []string{
		"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_REGION", "AWS_DEFAULT_REGION",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_EC2_METADATA_DISABLED",
	} {
		t.Setenv(name, "")
	}
	// the default chain ends at IMDS, which must not be contacted
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// captureFactory replaces KmsClientFactory for the test with one that
// records the config and options it is given and returns client.
func captureFactory(t *testing.T, client awskmscrypto.KmsClient) (*aws.Config, *kms.Options) {
	t.Helper()
	original := awskmscrypto.KmsClientFactory
	t.Cleanup(func() { awskmscrypto.KmsClientFactory = original })

	var cfg aws.Config
	var opts kms.Options
	awskmscrypto.KmsClientFactory = func(c aws.Config, optFns ...func(*kms.Options)) awskmscrypto.KmsClient {
		cfg = c
		for _, fn := range optFns {
			fn(&opts)
		}
		return client
	}
	return &cfg, &opts
}

func tokenCfg(attributes string) *mockTokenCfg {
	return &mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "unit",
		atts:         attributes,
	}
}

// TestInitCredentialsFromEnvironment checks that the SDK default chain
// resolves the environment credentials, which Init no longer copies into a
// static provider of its own (XPKI-034), and that the attributes set the
// region and endpoint.
func TestInitCredentialsFromEnvironment(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")
	client := newFakeKMS()
	cfg, opts := captureFactory(t, client)

	provider, err := awskmscrypto.KmsLoader(tokenCfg("Endpoint=http://localhost:14556, Region=eu-west-2"))
	require.NoError(t, err)
	assert.Equal(t, awskmscrypto.ProviderName, provider.Manufacturer())
	assert.Equal(t, "unit", provider.Model())
	assert.Same(t, client, awskmscrypto.Client(provider.(*awskmscrypto.Provider)))

	assert.Equal(t, "eu-west-2", cfg.Region)
	assert.Equal(t, "http://localhost:14556", aws.ToString(opts.BaseEndpoint))

	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIDEXAMPLE", creds.AccessKeyID)
	assert.Equal(t, "secret", creds.SecretAccessKey)
	assert.Equal(t, "token", creds.SessionToken)
	assert.False(t, creds.CanExpire)

	sources, ok := cfg.Credentials.(interface{ ProviderSources() []aws.CredentialSource })
	require.True(t, ok, "%T", cfg.Credentials)
	assert.Equal(t, []aws.CredentialSource{aws.CredentialSourceEnvVars}, sources.ProviderSources(), "resolved by the SDK chain from the environment")
}

// TestInitCredentialsFromSharedConfig checks that without environment
// credentials the SDK chain reads the shared config, including a region.
func TestInitCredentialsFromSharedConfig(t *testing.T) {
	isolateAWSEnv(t)
	dir := t.TempDir()
	credentialsFile := filepath.Join(dir, "credentials")
	writeFile(t, credentialsFile, "[default]\naws_access_key_id = AKIDSHARED\naws_secret_access_key = shared\n")
	configFile := filepath.Join(dir, "config")
	writeFile(t, configFile, "[default]\nregion = ap-south-1\n")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsFile)
	t.Setenv("AWS_CONFIG_FILE", configFile)
	cfg, opts := captureFactory(t, newFakeKMS())

	_, err := awskmscrypto.Init(tokenCfg(""))
	require.NoError(t, err)
	assert.Equal(t, "ap-south-1", cfg.Region, "region from the shared config")
	assert.Nil(t, opts.BaseEndpoint, "no endpoint attribute, no endpoint override")

	creds, err := cfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIDSHARED", creds.AccessKeyID)
	assert.Equal(t, "shared", creds.SecretAccessKey)
}

// TestInitRegionPrecedence checks that the Region attribute overrides the
// environment region, and that the environment sets the region otherwise.
func TestInitRegionPrecedence(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_REGION", "us-east-1")
	cfg, _ := captureFactory(t, newFakeKMS())

	_, err := awskmscrypto.Init(tokenCfg("Region=eu-central-1"))
	require.NoError(t, err)
	assert.Equal(t, "eu-central-1", cfg.Region)

	_, err = awskmscrypto.Init(tokenCfg("Endpoint=http://localhost:14556"))
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", cfg.Region)
}

// TestInitErrors checks the Init failures: a factory without a client and
// an SDK configuration that does not load.
func TestInitErrors(t *testing.T) {
	isolateAWSEnv(t)

	t.Run("no client", func(t *testing.T) {
		captureFactory(t, nil)
		_, err := awskmscrypto.KmsLoader(tokenCfg(""))
		require.EqualError(t, err, "KMS client factory returned no client")
	})
	t.Run("bad environment", func(t *testing.T) {
		t.Setenv("AWS_MAX_ATTEMPTS", "many")
		captureFactory(t, newFakeKMS())

		_, err := awskmscrypto.Init(tokenCfg(""))
		require.ErrorContains(t, err, "failed to load AWS configuration: ")
		require.ErrorContains(t, err, "AWS_MAX_ATTEMPTS")
	})
}

func TestParseKmsAttributes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		attributes string
		expected   map[string]string
	}{
		{
			name:       "empty",
			attributes: "",
			expected:   map[string]string{},
		},
		{
			name:       "one",
			attributes: "Region=us-west-2",
			expected:   map[string]string{"Region": "us-west-2"},
		},
		{
			name:       "two with spaces",
			attributes: " Endpoint = http://localhost:14556 , Region=eu-west-2 ",
			expected: map[string]string{
				"Endpoint": "http://localhost:14556",
				"Region":   "eu-west-2",
			},
		},
		{
			name:       "value with equals",
			attributes: "Endpoint=http://h/?a=b",
			expected:   map[string]string{"Endpoint": "http://h/?a=b"},
		},
		{
			name:       "no value",
			attributes: "Endpoint=,Region",
			expected:   map[string]string{"Endpoint": ""},
		},
		{
			name:       "last wins",
			attributes: "Region=a,Region=b",
			expected:   map[string]string{"Region": "b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, awskmscrypto.ParseKmsAttributes(tc.attributes))
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
