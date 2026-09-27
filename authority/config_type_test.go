package authority_test

import (
	"encoding/json"
	"testing"

	"github.com/effective-security/xpki/authority"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestIssuerConfigType checks that IssuerConfig.Type is read from the
// `type` key in YAML and JSON and written with the same casing as the other
// keys (XPKI-058).
func TestIssuerConfigType(t *testing.T) {
	var fromYAML authority.IssuerConfig
	require.NoError(t, yaml.Unmarshal([]byte("label: l1\ntype: ocsp\ncert: c.pem\n"), &fromYAML))
	assert.Equal(t, "ocsp", fromYAML.Type)
	assert.Equal(t, "l1", fromYAML.Label)

	var fromJSON authority.IssuerConfig
	require.NoError(t, json.Unmarshal([]byte(`{"label":"l1","type":"ocsp","cert":"c.pem"}`), &fromJSON))
	assert.Equal(t, "ocsp", fromJSON.Type)

	// the key written by both encoders is `type`, like the other keys, and
	// it is omitted when empty (it was `Type`, and `"Type":""`, in JSON)
	y, err := yaml.Marshal(&fromYAML)
	require.NoError(t, err)
	var ykeys map[string]any
	require.NoError(t, yaml.Unmarshal(y, &ykeys))
	assert.Equal(t, "ocsp", ykeys["type"])
	assert.NotContains(t, ykeys, "Type")

	j, err := json.Marshal(&fromJSON)
	require.NoError(t, err)
	var jkeys map[string]any
	require.NoError(t, json.Unmarshal(j, &jkeys))
	assert.Equal(t, "ocsp", jkeys["type"])
	assert.NotContains(t, jkeys, "Type")

	j, err = json.Marshal(&authority.IssuerConfig{Label: "l2"})
	require.NoError(t, err)
	jkeys = nil
	require.NoError(t, json.Unmarshal(j, &jkeys))
	assert.NotContains(t, jkeys, "type")
	assert.NotContains(t, jkeys, "Type")

	var back authority.IssuerConfig
	require.NoError(t, json.Unmarshal(j, &back))
	assert.Empty(t, back.Type)

	// the configuration files use the same key
	cfg, err := authority.LoadConfig("testdata/ca-config.dev.yaml")
	require.NoError(t, err)
	require.NotNil(t, cfg.Authority)
	require.NotEmpty(t, cfg.Authority.Issuers)
	assert.Equal(t, "trusty", cfg.Authority.Issuers[0].Type)
}
