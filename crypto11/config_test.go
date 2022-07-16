package crypto11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadConfigTwice(t *testing.T) {
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
}

func TestLoadConfigYaml(t *testing.T) {
	c, err := LoadTokenConfig("testdata/aws-dev-kms.yaml")
	require.NoError(t, err)

	c2, err := LoadTokenConfig("testdata/aws-dev-kms.json")
	require.NoError(t, err)

	assert.Equal(t, c, c2)
}
