package crypto11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadConfigTwice(t *testing.T) {
	requireP11(t)
	c, err := LoadTokenConfig(SoftHSMConfig)
	require.NoError(t, err)

	assert.NotEmpty(t, c.Path)
	assert.NotEmpty(t, c.Pin)
	assert.NotEmpty(t, c.TokenLabel)

	p11, err := Init(c)
	require.NoError(t, err)
	require.NotNil(t, p11)

	p11_2, err := Init(c)
	require.NoError(t, err)
	require.NotNil(t, p11_2)
	assert.Same(t, p11.Ctx, p11_2.Ctx)

	closeLib(t, p11)
	_, err = p11_2.GenRandom(make([]byte, 8))
	require.NoError(t, err)
	closeLib(t, p11_2)
}

func TestLoadConfigYaml(t *testing.T) {
	c, err := LoadTokenConfig("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml")
	require.NoError(t, err)

	c2, err := LoadTokenConfig("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json")
	require.NoError(t, err)

	assert.NotEqual(t, c, c2)
}
