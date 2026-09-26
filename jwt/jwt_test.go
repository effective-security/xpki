package jwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/internal/testenv"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
)

// kmsConfig and localKMSAddr are the local-kms fixture (make start-local-kms)
// used by Test_SignPrivateKMS; the endpoint is the one in kmsConfig.
const (
	kmsConfig    = "../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json"
	localKMSAddr = "localhost:14555"
)

func Test_Config(t *testing.T) {
	_, err := jwt.LoadProviderConfig("testdata/missing.json")
	assert.EqualError(t, err, "unable to read file: open testdata/missing.json: no such file or directory")

	_, err = jwt.LoadProviderConfig("testdata/jwtprov_corrupted.1.json")
	assert.EqualError(t, err, `unable parse JSON: testdata/jwtprov_corrupted.1.json: invalid character 'v' looking for beginning of value`)

	_, err = jwt.LoadProviderConfig("testdata/jwtprov_corrupted.yaml")
	assert.EqualError(t, err, `unable parse YAML: testdata/jwtprov_corrupted.yaml: yaml: line 3: did not find expected alphabetic or numeric character`)

	_, err = jwt.LoadProviderConfig("testdata/jwtprov_corrupted.2.json")
	assert.EqualError(t, err, `missing kid: "testdata/jwtprov_corrupted.2.json"`)

	_, err = jwt.LoadProviderConfig("testdata/jwtprov_no_kid.json")
	assert.EqualError(t, err, `missing kid: "testdata/jwtprov_no_kid.json"`)

	_, err = jwt.LoadProviderConfig("testdata/jwtprov_no_keys.json")
	assert.EqualError(t, err, `missing keys: "testdata/jwtprov_no_keys.json"`)

	cfg, err := jwt.LoadProviderConfig("testdata/jwtprov.json")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 2, len(cfg.Keys))
	assert.Equal(t, "1", cfg.KeyID)
	assert.Equal(t, "trusty.com", cfg.Issuer)
	assert.Equal(t, 8*time.Hour, time.Duration(cfg.TokenExpiry))
	//assert.Equal(t, jwtprov.trustyClient, cfg.DefaultRole)
	//assert.Equal(t, 2, len(cfg.RolesMap[jwtprov.trustyAdmin]))
}

func Test_Load(t *testing.T) {
	_, err := jwt.LoadProvider("testdata/missing.json", nil)
	require.Error(t, err)
	assert.Equal(t, "unable to read file: open testdata/missing.json: no such file or directory", err.Error())

	_, err = jwt.LoadProvider("testdata/jwtprov_corrupted.1.json", nil)
	require.Error(t, err)

	_, err = jwt.LoadProvider("testdata/jwtprov_corrupted.2.json", nil)
	require.Error(t, err)

	_, err = jwt.LoadProvider("testdata/jwtprov.json", nil)
	require.NoError(t, err)

	p, err := jwt.LoadProvider("testdata/jwtprov.yaml", nil)
	require.NoError(t, err)
	assert.Equal(t, 12*time.Hour, p.TokenExpiry())

	_, err = jwt.LoadProvider("testdata/jwtprov-kms.yaml", nil)
	assert.EqualError(t, err, "Crypto provider not provided to load private key")

	_, err = jwt.LoadProvider("", nil)
	assert.EqualError(t, err, "issuer not configured")

	assert.Panics(t, func() {
		jwt.MustNewProvider(&jwt.ProviderConfig{
			Issuer: "issuer",
		}, nil)
	})
}

func Test_SignSym(t *testing.T) {
	ctx := context.Background()
	p, err := jwt.LoadProvider("testdata/jwtprov.json", nil)
	require.NoError(t, err)
	p1, err := jwt.LoadProvider("testdata/jwtprov.1.json", nil)
	require.NoError(t, err)
	p2, err := jwt.LoadProvider("testdata/jwtprov.2.json", nil)
	require.NoError(t, err)

	extra := jwt.MapClaims{
		"cnf": "{}",
	}
	std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, 5*time.Minute, extra)
	token, err := p.Sign(ctx, std)
	require.NoError(t, err)
	assert.Equal(t, extra["cnf"], std["cnf"])

	cfg := &jwt.VerifyConfig{
		ExpectedIssuer:   p.Issuer(),
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	claims, err := p.ParseToken(ctx, token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)

	_, err = p2.ParseToken(ctx, token, cfg)
	assert.EqualError(t, err, "unable to verify token: invalid signature")

	cfg2 := &jwt.VerifyConfig{
		ExpectedIssuer:   p1.Issuer(),
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	_, err = p1.ParseToken(ctx, token, cfg2)
	assert.EqualError(t, err, "unable to verify token: invalid issuer")

	cfg.ExpectedAudience = []string{"aud"}
	_, err = p.ParseToken(ctx, token, cfg)
	assert.EqualError(t, err, "unable to verify token: token missing audience")

	cfg.ExpectedAudience = []string{"trusty.com"}
	cfg.ExpectedSubject = "subj"
	_, err = p.ParseToken(ctx, token, cfg)
	assert.EqualError(t, err, "unable to verify token: invalid subject")

	parser := jwt.TokenParser{
		ValidMethods: []string{"RS256"},
	}
	_, err = parser.Parse(token, nil, nil)
	assert.EqualError(t, err, "unsupported signing method: HS256")
}

func Test_SignPrivateRSA(t *testing.T) {
	ctx := context.Background()
	tcases := []int{2048, 3072, 4096}
	for _, tc := range tcases {
		ecKey, err := rsa.GenerateKey(rand.Reader, tc)
		require.NoError(t, err)

		pemKey, err := certutil.EncodePrivateKeyToPEM(ecKey)
		require.NoError(t, err)

		crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
		require.NoError(t, err)

		p, err := jwt.NewProvider(&jwt.ProviderConfig{
			Issuer:     "trusty.com",
			PrivateKey: string(pemKey),
		}, crypto)
		require.NoError(t, err)

		extra := jwt.MapClaims{
			"resource": "provenid.org",
		}
		std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, extra)
		token, err := p.Sign(ctx, std)

		require.NoError(t, err)

		cfg := &jwt.VerifyConfig{
			ExpectedSubject:  "denis@ekspand.com",
			ExpectedAudience: []string{"trusty.com"},
		}
		claims, err := p.ParseToken(ctx, token, cfg)
		require.NoError(t, err)
		assert.Equal(t, std, claims)

		jwt.TimeNowFn = func() time.Time {
			return time.Now().Add(24 * time.Hour)
		}
		_, err = p.ParseToken(ctx, token, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to verify token: token expired at:")
		jwt.TimeNowFn = time.Now
	}
}

func Test_SignPrivateEC(t *testing.T) {
	ctx := context.Background()
	tcases := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, tc := range tcases {
		ecKey, err := ecdsa.GenerateKey(tc, rand.Reader)
		require.NoError(t, err)

		pemKey, err := certutil.EncodePrivateKeyToPEM(ecKey)
		require.NoError(t, err)

		crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
		require.NoError(t, err)

		p, err := jwt.NewProvider(&jwt.ProviderConfig{
			Issuer:     "trusty.com",
			PrivateKey: string(pemKey),
		}, crypto)
		require.NoError(t, err)

		std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
		token, err := p.Sign(ctx, std)
		require.NoError(t, err)

		cfg := &jwt.VerifyConfig{
			ExpectedSubject:  "denis@ekspand.com",
			ExpectedAudience: []string{"trusty.com"},
		}
		claims, err := p.ParseToken(ctx, token, cfg)
		require.NoError(t, err)
		assert.Equal(t, std, claims)
	}
}

func Test_SignPrivateKMS(t *testing.T) {
	testenv.RequireTCP(t, "local-kms", localKMSAddr)
	ctx := context.Background()
	cryptoProv, err := cryptoprov.Load(kmsConfig, nil)
	require.NoError(t, err)

	prov := cryptoProv.Default()
	pvk, err := prov.GenerateECDSAKey("Test_SignPrivateKMS", elliptic.P256())
	require.NoError(t, err)

	id, _, err := prov.IdentifyKey(pvk)
	require.NoError(t, err)
	url, _, err := prov.ExportKey(id)
	require.NoError(t, err)
	/*
		assert.NotEmpty(t, url)
		assert.NotEmpty(t, b)

		prov, pvk, err = crypto.LoadPrivateKey([]byte(url))
	*/

	p, err := jwt.NewProvider(&jwt.ProviderConfig{
		Issuer:     "trusty.com",
		PrivateKey: url,
	}, cryptoProv)
	require.NoError(t, err)

	std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
	token, err := p.Sign(ctx, std)
	require.NoError(t, err)

	cfg := &jwt.VerifyConfig{
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	claims, err := p.ParseToken(ctx, token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)

	opt := jwt.WithHeaders(map[string]any{
		"typ": "custom",
	})
	p, err = jwt.NewProviderFromCryptoSigner(pvk.(crypto.Signer), opt)
	require.NoError(t, err)

	std = jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
	token, err = p.Sign(ctx, std)
	require.NoError(t, err)
	assert.NotNil(t, p.PublicKey())

	claims, err = p.ParseToken(ctx, token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)
}

// Test_ParseToken_SignatureBeforeClaims verifies that the signature is
// checked before claims validation, so a tampered payload is reported as a
// signature failure rather than as a claims failure (XPKI-069).
func Test_ParseToken_SignatureBeforeClaims(t *testing.T) {
	ctx := context.Background()
	p, err := jwt.LoadProvider("testdata/jwtprov.json", nil)
	require.NoError(t, err)

	std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, 5*time.Minute, nil)
	token, err := p.Sign(ctx, std)
	require.NoError(t, err)

	cfg := &jwt.VerifyConfig{
		ExpectedIssuer:   p.Issuer(),
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	_, err = p.ParseToken(ctx, token, cfg)
	require.NoError(t, err)

	t.Run("tampered_payload", func(t *testing.T) {
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)
		payload, err := jwt.DecodeSegment(parts[1])
		require.NoError(t, err)
		tampered := jwt.MapClaims{}
		require.NoError(t, json.Unmarshal(payload, &tampered))
		tampered["sub"] = "attacker"
		js, err := json.Marshal(tampered)
		require.NoError(t, err)
		parts[1] = jwt.EncodeSegment(js)

		// the subject no longer matches cfg; with claims validated first
		// this would have surfaced as "invalid subject"
		_, err = p.ParseToken(ctx, strings.Join(parts, "."), cfg)
		assert.EqualError(t, err, "unable to verify token: invalid signature")
	})

	t.Run("valid_signature_expired", func(t *testing.T) {
		jwt.TimeNowFn = func() time.Time {
			return time.Now().Add(24 * time.Hour)
		}
		defer func() { jwt.TimeNowFn = time.Now }()

		_, err := p.ParseToken(ctx, token, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to verify token: token expired at:")
	})
}

func Test_ParseToken_FractionalExp(t *testing.T) {
	ctx := context.Background()
	p, err := jwt.LoadProvider("testdata/jwtprov.json", nil)
	require.NoError(t, err)

	cfg := &jwt.VerifyConfig{
		ExpectedIssuer: p.Issuer(),
	}

	// The parser decodes claims as json.Number; a fractional exp must be
	// validated like an integer one, not silently treated as absent.
	t.Run("expired", func(t *testing.T) {
		claims := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), nil, 5*time.Minute, nil)
		claims["exp"] = float64(time.Now().Add(-time.Hour).Unix()) + 0.5
		token, err := p.Sign(ctx, claims)
		require.NoError(t, err)

		_, err = p.ParseToken(ctx, token, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token expired at:")
	})

	t.Run("valid", func(t *testing.T) {
		claims := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), nil, 5*time.Minute, nil)
		claims["exp"] = float64(time.Now().Add(time.Hour).Unix()) + 0.5
		token, err := p.Sign(ctx, claims)
		require.NoError(t, err)

		parsed, err := p.ParseToken(ctx, token, cfg)
		require.NoError(t, err)
		require.NotNil(t, parsed.Time("exp"))
	})
}

// TestProviderHeaderValidation checks that no constructor accepts headers
// that would make a token disagree with how it is signed (XPKI-104).
func TestProviderHeaderValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg, err := jwt.LoadProviderConfig("testdata/jwtprov.json")
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	newConfig := func(ops ...jwt.Option) (jwt.Provider, error) {
		return jwt.NewProvider(cfg, nil, ops...)
	}
	newSigner := func(ops ...jwt.Option) (jwt.Provider, error) {
		return jwt.NewProviderFromCryptoSigner(ecKey, ops...)
	}

	tcs := []struct {
		name    string
		create  func(...jwt.Option) (jwt.Provider, error)
		headers map[string]any
		expKid  any
		expErr  string
	}{
		{name: "config: signing kid", create: newConfig, headers: map[string]any{"kid": "1"}, expKid: "1"},
		{name: "config: typ", create: newConfig, headers: map[string]any{"typ": "at+jwt"}, expKid: "1"},
		{name: "config: other ring kid", create: newConfig, headers: map[string]any{"kid": "0"}, expErr: `kid header 0 does not match the signing key "1"`},
		{name: "config: unknown kid", create: newConfig, headers: map[string]any{"kid": "9"}, expErr: `kid header 9 does not match the signing key "1"`},
		{name: "config: numeric kid", create: newConfig, headers: map[string]any{"kid": 1}, expErr: `kid header 1 does not match the signing key "1"`},
		{name: "config: nil kid", create: newConfig, headers: map[string]any{"kid": nil}, expErr: `kid header <nil> does not match the signing key "1"`},
		{name: "config: alg", create: newConfig, headers: map[string]any{"alg": "RS256"}, expErr: "alg header RS256 does not match the signing algorithm HS256"},
		{name: "signer: kid", create: newSigner, headers: map[string]any{"kid": "any"}, expKid: "any"},
		{name: "signer: same alg", create: newSigner, headers: map[string]any{"alg": "ES256"}},
		{name: "signer: alg", create: newSigner, headers: map[string]any{"alg": "HS256"}, expErr: "alg header HS256 does not match the signing algorithm ES256"},
		{name: "signer: numeric alg", create: newSigner, headers: map[string]any{"alg": 1}, expErr: "alg header 1 does not match the signing algorithm ES256"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := tc.create(jwt.WithHeaders(tc.headers))
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
				assert.Nil(t, p)
				return
			}
			require.NoError(t, err)
			token, err := p.Sign(ctx, jwt.MapClaims{"sub": "subject"})
			require.NoError(t, err)
			header := tokenHeader(t, token)
			assert.Equal(t, tc.expKid, header["kid"])
			for k, v := range tc.headers {
				assert.Equal(t, v, header[k], k)
			}

			claims, err := p.ParseToken(ctx, token, nil)
			require.NoError(t, err)
			assert.Equal(t, "subject", claims.String("sub"))
		})
	}
}
