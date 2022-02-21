package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestSigner(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := dpop.NewSigner(ecKey)
	require.NoError(t, err)
	assert.NotEmpty(t, signer.JWKThumbprint())

	rsReq, err := http.NewRequest(http.MethodGet, "https://cisco.com/api/signer?q=notincluded", nil)
	require.NoError(t, err)

	token, err := signer.ForRequest(rsReq, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	assert.Equal(t, token, rsReq.Header.Get(dpop.HTTPHeader))

	res, err := dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
	require.NoError(t, err)
	assert.NotNil(t, res.Key)
	require.NotNil(t, res.Claims)
	assert.Empty(t, res.Claims.Issuer)
	assert.Empty(t, res.Claims.Subject)
	assert.Empty(t, res.Claims.Audience)
	assert.Equal(t, "https://cisco.com/api/signer", res.Claims.HTTPUri)
	assert.Equal(t, http.MethodGet, res.Claims.HTTPMethod)

	_, err = dpop.VerifyClaims(dpop.VerifyConfig{ExpectedIssuer: "myissuer"}, rsReq)
	assert.EqualError(t, err, "dpop: invalid issuer: ''")
	_, err = dpop.VerifyClaims(dpop.VerifyConfig{ExpectedSubject: "mysubj"}, rsReq)
	assert.EqualError(t, err, "dpop: invalid subject: ''")
	_, err = dpop.VerifyClaims(dpop.VerifyConfig{ExpectedAudience: "myau"}, rsReq)
	assert.EqualError(t, err, "dpop: invalid audience: []")
	_, err = dpop.VerifyClaims(dpop.VerifyConfig{ExpectedNonce: "tqwueytr35r"}, rsReq)
	assert.EqualError(t, err, "dpop: invalid nonce: ''")
}

func TestVerifyClaims(t *testing.T) {
	rsReq, err := http.NewRequest(http.MethodGet, "https://cisco.com/api/signer?q=notincluded", nil)
	require.NoError(t, err)

	t.Run("no header", func(t *testing.T) {
		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: HTTP Header not present in request")
	})

	t.Run("invalid header", func(t *testing.T) {
		rsReq.Header.Set(dpop.HTTPHeader, "invalid")
		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: failed to parse header: square/go-jose: compact JWS format must have three parts")
	})
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jsk := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       ecKey,
	}

	t.Run("no typ", func(t *testing.T) {
		s, err := jose.NewSigner(jsk, &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderContentType: "unsupported",
			},
		})
		require.NoError(t, err)
		ts := &testSigner{
			signingKey: jsk,
			signer:     s,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: typ field not found in header")
	})

	t.Run("multiple headers", func(t *testing.T) {
		s, err := jose.NewSigner(jsk, &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderContentType: "unsupported",
				jose.HeaderType:        "invalid",
			},
		})
		require.NoError(t, err)
		ts := &testSigner{
			signingKey: jsk,
			signer:     s,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: invalid typ header")
	})

	t.Run("no empebbded key", func(t *testing.T) {
		s, err := jose.NewSigner(jsk, &jose.SignerOptions{
			//EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderType: "dpop+jwt",
			},
		})
		require.NoError(t, err)
		ts := &testSigner{
			signingKey: jsk,
			signer:     s,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: jwk field not found in header")
	})

	s, err := jose.NewSigner(jsk, &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: "dpop+jwt",
		},
	})
	require.NoError(t, err)

	t.Run("no jti", func(t *testing.T) {
		ts := &testSigner{
			signingKey: jsk,
			signer:     s,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: claim not found: jti")
	})

	t.Run("no HTTPMethod", func(t *testing.T) {
		ts := &testSigner{
			signingKey: jsk,
			signer:     s,
			withJTI:    true,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: claim not found: http_method")
	})

	t.Run("no HTTPURL", func(t *testing.T) {
		ts := &testSigner{
			signingKey:     jsk,
			signer:         s,
			withJTI:        true,
			withHTTPMethod: true,
			//withHTTPURL:    true,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: claim not found: http_uri")
	})

	t.Run("Invalid method", func(t *testing.T) {
		ts := &testSigner{
			signingKey:     jsk,
			signer:         s,
			withJTI:        true,
			withHTTPMethod: true,
			withHTTPURL:    true,
		}
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		rsReq.Method = "POST"
		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: claim mismatch: http_method: 'GET'")
		rsReq.Method = http.MethodGet
	})

	t.Run("Invalid http_uri", func(t *testing.T) {
		ts := &testSigner{
			signingKey:     jsk,
			signer:         s,
			withJTI:        true,
			withHTTPMethod: true,
			withHTTPURL:    true,
		}
		rsReq.Method = http.MethodGet
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		rsReq.URL.Path = "wrong"

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: http_uri claim mismatch: wrong")
	})

	t.Run("Invalid host", func(t *testing.T) {
		ts := &testSigner{
			signingKey:     jsk,
			signer:         s,
			withJTI:        true,
			withHTTPMethod: true,
			withHTTPURL:    true,
		}
		rsReq.URL.Path = "/api/signer"
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)
		rsReq.Host = "local"

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		assert.EqualError(t, err, "dpop: http_uri claim mismatch: local")
	})
	t.Run("expired", func(t *testing.T) {
		ts := &testSigner{
			signingKey:     jsk,
			signer:         s,
			withJTI:        true,
			withHTTPMethod: true,
			withHTTPURL:    true,
			timeNowFn: func() time.Time {
				return time.Now().Add(-time.Hour)
			},
		}
		rsReq.Host = "cisco.com"
		err = ts.ForRequest(rsReq, nil)
		require.NoError(t, err)

		_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, rsReq)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dpop: iat claim expired")
	})
}

func TestParse(t *testing.T) {
	dp := `eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRwb3Arand0IiwgImp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIk1wTmlIR1RkXzNYY240NDVVR0FlN09KY1NTekFXU2JSUWFXdWlZcW5kYzQiLCAieSI6ICJlOUMzWVAwMkdHOHVhUE5fZEUzOUNESEs3cDFyQm1HZXVUcXptNEZSMGI4In19.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9hcGkudGVzdC5wcm92ZWlkLmRldi92MS9kcG9wL3Rva2VuIiwiaWF0IjoxNjQ1MjA0OTI3LCJqdGkiOiIxQlJNbUZHSkVZX01MN3pLZjEwaWhxVTJuRjk0Wk01clhyUnlET1g0Rk0wIn0.mMUL2A-TE1L7i8J9cbxLAiuDOT0OpnATcaoyQKpq_ji7FO8WsFV_rf2TIFugA9NV4lk-QfBJAse5Ny5pRtHVLg`
	r, _ := http.NewRequest(http.MethodPost, "https://api.test.proveid.dev/v1/dpop/token", nil)
	r.Header.Set(dpop.HTTPHeader, dp)

	_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

type testSigner struct {
	signingKey jose.SigningKey
	signer     jose.Signer

	timeNowFn func() time.Time

	withJTI        bool
	withHTTPMethod bool
	withHTTPURL    bool
}

func (p *testSigner) ForRequest(r *http.Request, extraClaims interface{}) error {
	now := time.Now()
	if p.timeNowFn != nil {
		now = p.timeNowFn()
	}
	notBefore := now.Add(dpop.DefaultNotBefore)
	exp := now.Add(dpop.DefaultExpiration)
	claims := &jwt.Claims{
		NotBefore: jwt.NewNumericDate(notBefore),
		Expiry:    jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	if p.withJTI {
		claims.ID = certutil.RandomString(16)
	}

	builder := jwt.Signed(p.signer)
	builder = builder.Claims(claims)

	if p.withHTTPMethod {
		builder = builder.Claims(map[string]interface{}{
			"htm": r.Method,
		})
	}

	if p.withHTTPURL {
		coreURL := url.URL{
			Scheme: r.URL.Scheme,
			Opaque: r.URL.Opaque,
			Host:   r.URL.Host,
			Path:   r.URL.Path,
		}
		builder = builder.Claims(map[string]interface{}{
			"htu": coreURL.String(),
		})
	}

	if extraClaims != nil {
		builder = builder.Claims(extraClaims)
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return errors.WithStack(err)
	}

	r.Header.Set(dpop.HTTPHeader, token)
	return nil
}
