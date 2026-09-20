package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/jwt"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParserConfigurationFiles(t *testing.T) {
	cfg, err := jwt.LoadParserConfig("")
	require.NoError(t, err)
	assert.Equal(t, &jwt.ParserConfig{}, cfg)
	dir := t.TempDir()
	_, err = jwt.LoadParserConfig(filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
	file := filepath.Join(dir, "parser.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"issuer":"https://issuer.example.test","jwks":{"keys":[]}}`), 0600))
	cfg, err = jwt.LoadParserConfig(file)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.test", cfg.Issuer)
	require.NotNil(t, cfg.JWKeySet)
	assert.Empty(t, cfg.JWKeySet.Keys)
	require.NoError(t, os.WriteFile(file, []byte(`{`), 0600))
	_, err = jwt.LoadParserConfig(file)
	require.Error(t, err)
	parser, err := jwt.NewParser(&jwt.ParserConfig{})
	require.NoError(t, err)
	parser.SetRevocation(nil)
	assert.Nil(t, parser.GetRevocation())
	_, err = parser.ParseToken(context.Background(), "token", nil)
	require.EqualError(t, err, "verifier not configured")
}

func TestTokenParserMalformedSegments(t *testing.T) {
	header := jwt.EncodeSegment([]byte(`{"alg":"HS256"}`))
	claims := jwt.EncodeSegment([]byte(`{"sub":"subject"}`))
	for _, tc := range []struct{ name, token, want string }{
		{"segments", "one.two", "malformed token"},
		{"header base64", "%." + claims + ".sig", "failed to decode token"},
		{"header JSON", jwt.EncodeSegment([]byte("{")) + "." + claims + ".sig", "failed to unmarshal header"},
		{"claims base64", header + ".%.sig", "failed to decode token"},
		{"claims JSON", header + "." + jwt.EncodeSegment([]byte("{")) + ".sig", "failed to decode token"},
		{"missing algorithm", jwt.EncodeSegment([]byte(`{}`)) + "." + claims + ".sig", "invalid token: no alg specified"},
		{"numeric algorithm", jwt.EncodeSegment([]byte(`{"alg":1}`)) + "." + claims + ".sig", "invalid token: no alg specified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parser := jwt.TokenParser{}
			token, _, err := parser.ParseUnverified(tc.token, jwt.MapClaims{})
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, token)
		})
	}
}

func TestStandaloneSymmetricProvider(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	provider, err := jwt.NewProviderWithSymmetricKey(key)
	require.NoError(t, err)
	token, err := provider.Sign(context.Background(), jwt.MapClaims{"sub": "subject"})
	require.NoError(t, err)
	parser := jwt.TokenParser{ValidMethods: []string{"HS256"}}
	parsed, err := parser.Parse(token, nil, func(*jwt.Token) (any, error) { return key, nil })
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	// XPKI-066: the standalone symmetric provider has no verification key ring.
	_, err = provider.ParseToken(context.Background(), token, nil)
	require.ErrorContains(t, err, "missing kid")
	parser.ValidMethods = []string{"RS256"}
	_, err = parser.Parse(token, nil, func(*jwt.Token) (any, error) {
		t.Fatal("disallowed methods must not reach key lookup")
		return nil, nil
	})
	require.EqualError(t, err, "unsupported signing method: HS256")
	// XPKI-104: this constructor leaves the headers map nil before applying options.
	assert.Panics(t, func() { _, _ = jwt.NewProviderWithSymmetricKey(key, jwt.WithHeaders(map[string]any{"kid": "test"})) })
}

func TestParserKeyIDTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		kid  any
		want string
	}{
		{"string", "42", ""}, {"numeric", 42, ""}, {"invalid", true, "invalid kid header type: bool"}, {"unknown", "missing", "key not found: missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := jwt.NewProviderFromCryptoSigner(key, jwt.WithHeaders(map[string]any{"kid": tc.kid}))
			require.NoError(t, err)
			token, err := provider.Sign(context.Background(), jwt.MapClaims{"sub": "subject"})
			require.NoError(t, err)
			parser, err := jwt.NewParser(&jwt.ParserConfig{JWKeySet: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:   key.Public(),
				KeyID: "42",
			}}}})
			require.NoError(t, err)
			claims, err := parser.ParseToken(context.Background(), token, nil)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
				assert.Nil(t, claims)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "subject", claims.String("sub"))
			}
		})
	}
}

func TestClaimStringConversions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{"nil", nil, nil}, {"scalar", "scope", []string{"scope"}}, {"typed slice", []string{"a", "b"}, []string{"a", "b"}},
		{"mixed", []any{"a", 42, true, nil}, []string{"a", "42", "true", "<nil>"}}, {"unsupported", 42, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"value": tc.value}
			assert.Equal(t, tc.want, claims.Strings("value"))
		})
	}
	var missing jwt.MapClaims
	assert.Nil(t, missing.Strings("missing"))
	assert.Nil(t, (jwt.MapClaims{}).Strings("missing"))
	for _, tc := range []struct {
		value any
		want  string
	}{{uint64(42), "42"}, {int64(-42), "-42"}, {json.Number("1.5"), "1.5"}, {true, "true"}, {false, "false"}} {
		assert.Equal(t, tc.want, (jwt.MapClaims{"value": tc.value}).String("value"))
	}
	assert.Nil(t, (jwt.MapClaims{"value": 42}).StringsMap("value"))
	assert.Equal(t, map[string]string{
		"a": "42",
		"b": "true",
	}, (jwt.MapClaims{"value": map[string]any{
		"a": 42,
		"b": true,
	}}).StringsMap("value"))
	// Claims with non-JSON values must surface serialization failures.
	err := jwt.MapClaims{"value": make(chan int)}.To(&struct{}{})
	require.Error(t, err)
}
