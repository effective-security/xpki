package jwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
)

func Test_Config(t *testing.T) {
	_, err := jwt.LoadConfig("testdata/missing.json")
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.json: no such file or directory", err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.1.json")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal JSON: "testdata/jwtprov_corrupted.1.json": invalid character 'v' looking for beginning of value`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.yaml")
	require.Error(t, err)
	assert.Equal(t, `unable to unmarshal YAML: "testdata/jwtprov_corrupted.yaml": yaml: line 3: did not find expected alphabetic or numeric character`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_corrupted.2.json")
	require.Error(t, err)
	assert.Equal(t, `missing kid: "testdata/jwtprov_corrupted.2.json"`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_no_kid.json")
	require.Error(t, err)
	assert.Equal(t, `missing kid: "testdata/jwtprov_no_kid.json"`, err.Error())

	_, err = jwt.LoadConfig("testdata/jwtprov_no_keys.json")
	require.Error(t, err)
	assert.Equal(t, `missing keys: "testdata/jwtprov_no_keys.json"`, err.Error())

	cfg, err := jwt.LoadConfig("testdata/jwtprov.json")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 2, len(cfg.Keys))
	assert.Equal(t, "1", cfg.KeyID)
	assert.Equal(t, "trusty.com", cfg.Issuer)
	//assert.Equal(t, jwtprov.trustyClient, cfg.DefaultRole)
	//assert.Equal(t, 2, len(cfg.RolesMap[jwtprov.trustyAdmin]))
}

func Test_Load(t *testing.T) {
	_, err := jwt.Load("testdata/missing.json", nil)
	require.Error(t, err)
	assert.Equal(t, "open testdata/missing.json: no such file or directory", err.Error())

	_, err = jwt.Load("testdata/jwtprov_corrupted.1.json", nil)
	require.Error(t, err)

	_, err = jwt.Load("testdata/jwtprov_corrupted.2.json", nil)
	require.Error(t, err)

	_, err = jwt.Load("testdata/jwtprov.json", nil)
	require.NoError(t, err)

	_, err = jwt.Load("testdata/jwtprov.yaml", nil)
	require.NoError(t, err)

	_, err = jwt.Load("testdata/jwtprov-kms.yaml", nil)
	assert.EqualError(t, err, "Crypto provider not provided to load private key")

	_, err = jwt.Load("", nil)
	assert.EqualError(t, err, "issuer not configured")

	assert.Panics(t, func() {
		jwt.MustNew(&jwt.Config{
			Issuer: "issuer",
		}, nil)
	})
}

func Test_SignSym(t *testing.T) {
	p, err := jwt.Load("testdata/jwtprov.json", nil)
	require.NoError(t, err)
	p1, err := jwt.Load("testdata/jwtprov.1.json", nil)
	require.NoError(t, err)
	p2, err := jwt.Load("testdata/jwtprov.2.json", nil)
	require.NoError(t, err)

	extra := jwt.MapClaims{
		"cnf": "{}",
	}
	std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, extra)
	token, err := p.Sign(std)
	require.NoError(t, err)
	assert.Equal(t, extra["cnf"], std["cnf"])

	cfg := jwt.VerifyConfig{
		ExpectedIssuer:   p.Issuer(),
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	claims, err := p.ParseToken(token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)

	_, err = p2.ParseToken(token, cfg)
	assert.EqualError(t, err, "failed to verify token: invalid signature")

	cfg2 := cfg
	cfg2.ExpectedIssuer = p1.Issuer()
	_, err = p1.ParseToken(token, cfg2)
	assert.EqualError(t, err, "failed to verify token: invalid issuer: trusty.com, expected: trusty1.com")

	cfg.ExpectedAudience = []string{"aud"}
	_, err = p.ParseToken(token, cfg)
	assert.EqualError(t, err, "failed to verify token: token missing audience: aud")

	cfg.ExpectedAudience = []string{"trusty.com"}
	cfg.ExpectedSubject = "subj"
	_, err = p.ParseToken(token, cfg)
	assert.EqualError(t, err, "failed to verify token: invalid subject: denis@ekspand.com, expected: subj")

	parser := jwt.TokenParser{
		ValidMethods: []string{"RS256"},
	}
	_, err = parser.Parse(token, jwt.VerifyConfig{}, nil)
	assert.EqualError(t, err, "unsupported signing method: HS256")
}

func Test_SignPrivateRSA(t *testing.T) {
	tcases := []int{2048, 3072, 4096}
	for _, tc := range tcases {
		ecKey, err := rsa.GenerateKey(rand.Reader, tc)
		require.NoError(t, err)

		pemKey, err := certutil.EncodePrivateKeyToPEM(ecKey)
		require.NoError(t, err)

		crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
		require.NoError(t, err)

		p, err := jwt.New(&jwt.Config{
			Issuer:     "trusty.com",
			PrivateKey: string(pemKey),
		}, crypto)
		require.NoError(t, err)

		extra := jwt.MapClaims{
			"resource": "provenid.org",
		}
		std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, extra)
		token, err := p.Sign(std)

		require.NoError(t, err)

		cfg := jwt.VerifyConfig{
			ExpectedSubject:  "denis@ekspand.com",
			ExpectedAudience: []string{"trusty.com"},
		}
		claims, err := p.ParseToken(token, cfg)
		require.NoError(t, err)
		assert.Equal(t, std, claims)

		jwt.TimeNowFn = func() time.Time {
			return time.Now().Add(24 * time.Hour)
		}
		_, err = p.ParseToken(token, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify token: token expired at:")
		jwt.TimeNowFn = time.Now
	}
}

func Test_SignPrivateEC(t *testing.T) {
	tcases := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, tc := range tcases {
		ecKey, err := ecdsa.GenerateKey(tc, rand.Reader)
		require.NoError(t, err)

		pemKey, err := certutil.EncodePrivateKeyToPEM(ecKey)
		require.NoError(t, err)

		crypto, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
		require.NoError(t, err)

		p, err := jwt.New(&jwt.Config{
			Issuer:     "trusty.com",
			PrivateKey: string(pemKey),
		}, crypto)
		require.NoError(t, err)

		std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
		token, err := p.Sign(std)
		require.NoError(t, err)

		cfg := jwt.VerifyConfig{
			ExpectedSubject:  "denis@ekspand.com",
			ExpectedAudience: []string{"trusty.com"},
		}
		claims, err := p.ParseToken(token, cfg)
		require.NoError(t, err)
		assert.Equal(t, std, claims)
	}
}

func Test_SignPrivateKMS(t *testing.T) {
	cryptoProv, err := cryptoprov.Load("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json", nil)
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

	p, err := jwt.New(&jwt.Config{
		Issuer:     "trusty.com",
		PrivateKey: url,
	}, cryptoProv)
	require.NoError(t, err)

	std := jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
	token, err := p.Sign(std)
	require.NoError(t, err)

	cfg := jwt.VerifyConfig{
		ExpectedSubject:  "denis@ekspand.com",
		ExpectedAudience: []string{"trusty.com"},
	}
	claims, err := p.ParseToken(token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)

	opt := jwt.WithHeaders(map[string]interface{}{
		"typ": "custom",
	})
	p, err = jwt.NewFromCryptoSigner(pvk.(crypto.Signer), opt)
	require.NoError(t, err)

	std = jwt.CreateClaims("", "denis@ekspand.com", p.Issuer(), []string{"trusty.com"}, time.Minute, nil)
	token, err = p.Sign(std)
	require.NoError(t, err)
	assert.NotNil(t, p.PublicKey())

	claims, err = p.ParseToken(token, cfg)
	require.NoError(t, err)
	assert.Equal(t, std, claims)
}
