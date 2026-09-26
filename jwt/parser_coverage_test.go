package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// tokenHeader returns the decoded JOSE header of a compact token.
func tokenHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := jwt.DecodeSegment(parts[0])
	require.NoError(t, err)
	header := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &header))
	return header
}

func newSymmetricKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestStandaloneSymmetricProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := newSymmetricKey(t)
	provider, err := jwt.NewProviderWithSymmetricKey(key)
	require.NoError(t, err)
	token, err := provider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
	require.NoError(t, err)

	// the header is unchanged for external HS256 verifiers: no kid
	header := tokenHeader(t, token)
	assert.Equal(t, "HS256", header["alg"])
	assert.Equal(t, "JWT", header["typ"])
	assert.NotContains(t, header, "kid")

	// XPKI-066: the provider verifies its own kid-less tokens
	claims, err := provider.ParseToken(ctx, token, nil)
	require.NoError(t, err)
	assert.Equal(t, "subject", claims.String("sub"))

	// independent verification with the raw key
	parser := jwt.TokenParser{ValidMethods: []string{"HS256"}}
	parsed, err := parser.Parse(token, nil, func(*jwt.Token) (any, error) { return key, nil })
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	parser.ValidMethods = []string{"RS256"}
	_, err = parser.Parse(token, nil, func(*jwt.Token) (any, error) {
		t.Fatal("disallowed methods must not reach key lookup")
		return nil, nil
	})
	require.EqualError(t, err, "unsupported signing method: HS256")

	// a different key does not verify
	other, err := jwt.NewProviderWithSymmetricKey(newSymmetricKey(t))
	require.NoError(t, err)
	_, err = other.ParseToken(ctx, token, nil)
	require.EqualError(t, err, "unable to verify token: invalid signature")

	// tampered claims do not verify
	parts := strings.Split(token, ".")
	parts[1] = jwt.EncodeSegment([]byte(`{"sub":"admin"}`))
	_, err = provider.ParseToken(ctx, strings.Join(parts, "."), nil)
	require.EqualError(t, err, "unable to verify token: invalid signature")

	// an asymmetric token is not verified with the symmetric key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecProvider, err := jwt.NewProviderFromCryptoSigner(ecKey)
	require.NoError(t, err)
	ecToken, err := ecProvider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
	require.NoError(t, err)
	_, err = provider.ParseToken(ctx, ecToken, nil)
	require.ErrorContains(t, err, "unable to verify token: invalid key type for ECDSA signature")

	// the provider keeps its own copy of the key
	key[0] ^= 0xff
	_, err = provider.ParseToken(ctx, token, nil)
	require.NoError(t, err)
}

func TestStandaloneSymmetricProviderKeyID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := newSymmetricKey(t)
	sign := func(t *testing.T, ops ...jwt.Option) string {
		t.Helper()
		p, err := jwt.NewProviderWithSymmetricKey(key, ops...)
		require.NoError(t, err)
		token, err := p.Sign(ctx, jwt.MapClaims{"sub": "subject"})
		require.NoError(t, err)
		return token
	}
	noKid := sign(t)
	k1 := sign(t, jwt.WithHeaders(map[string]any{"kid": "k1"}))
	k2 := sign(t, jwt.WithHeaders(map[string]any{"kid": "k2"}))
	assert.Equal(t, "k1", tokenHeader(t, k1)["kid"])

	// XPKI-104: a custom kid no longer panics, and the provider verifies it
	withKid, err := jwt.NewProviderWithSymmetricKey(key, jwt.WithHeaders(map[string]any{"kid": "k1"}))
	require.NoError(t, err)
	plain, err := jwt.NewProviderWithSymmetricKey(key)
	require.NoError(t, err)

	tcs := []struct {
		name     string
		provider jwt.Provider
		token    string
		expErr   string
	}{
		{name: "kid provider, own kid", provider: withKid, token: k1},
		{name: "kid provider, no kid", provider: withKid, token: noKid},
		{name: "kid provider, other kid", provider: withKid, token: k2, expErr: "unable to verify token: unexpected kid"},
		{name: "plain provider, no kid", provider: plain, token: noKid},
		{name: "plain provider, kid", provider: plain, token: k1, expErr: "unable to verify token: unexpected kid"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims, err := tc.provider.ParseToken(ctx, tc.token, nil)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				assert.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "subject", claims.String("sub"))
		})
	}
}

func TestStandaloneSymmetricProviderOptions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := newSymmetricKey(t)

	tcs := []struct {
		name      string
		ops       []jwt.Option
		expHeader map[string]any
		expErr    string
	}{
		{name: "nil headers", ops: []jwt.Option{jwt.WithHeaders(nil)}, expHeader: map[string]any{"alg": "HS256", "typ": "JWT"}},
		{name: "empty headers", ops: []jwt.Option{jwt.WithHeaders(map[string]any{})}, expHeader: map[string]any{"alg": "HS256", "typ": "JWT"}},
		{
			name:      "custom headers",
			ops:       []jwt.Option{jwt.WithHeaders(map[string]any{"typ": "at+jwt", "x5t": "abc"})},
			expHeader: map[string]any{"alg": "HS256", "typ": "at+jwt", "x5t": "abc"},
		},
		{
			name: "last option wins",
			ops: []jwt.Option{
				jwt.WithHeaders(map[string]any{"kid": "a", "typ": "one"}),
				jwt.WithHeaders(map[string]any{"kid": "b"}),
			},
			expHeader: map[string]any{"alg": "HS256", "typ": "one", "kid": "b"},
		},
		{name: "same alg", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"alg": "HS256"})}, expHeader: map[string]any{"alg": "HS256", "typ": "JWT"}},
		{name: "other alg", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"alg": "HS512"})}, expErr: "alg header HS512 does not match the signing algorithm HS256"},
		{name: "none alg", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"alg": "none"})}, expErr: "alg header none does not match the signing algorithm HS256"},
		{name: "empty kid", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"kid": ""})}, expErr: "kid header must be a nonempty string: "},
		{name: "numeric kid", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"kid": 42})}, expErr: "kid header must be a nonempty string: 42"},
		{name: "nil kid", ops: []jwt.Option{jwt.WithHeaders(map[string]any{"kid": nil})}, expErr: "kid header must be a nonempty string: <nil>"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := jwt.NewProviderWithSymmetricKey(key, tc.ops...)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				assert.Nil(t, p)
				return
			}
			require.NoError(t, err)
			token, err := p.Sign(ctx, jwt.MapClaims{"sub": "subject"})
			require.NoError(t, err)
			header := tokenHeader(t, token)
			assert.NotEmpty(t, header["jti"])
			delete(header, "jti")
			assert.Equal(t, tc.expHeader, header)

			_, err = p.ParseToken(ctx, token, nil)
			require.NoError(t, err)
		})
	}

	for _, k := range [][]byte{nil, {}} {
		p, err := jwt.NewProviderWithSymmetricKey(k)
		require.EqualError(t, err, "symmetric key is empty")
		assert.Nil(t, p)
	}
}

func TestParserKeyIDTypes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		kid  any
		want string
	}{
		{"string", "42", ""}, {"numeric", 42, ""}, {"invalid", true, "invalid kid header type: bool"}, {"unknown", "missing", `kid="missing": key not found`},
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
