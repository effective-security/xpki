package oauth2client

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"golang.org/x/oauth2"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki/jwt", "oauth2client")

// Client of OAuth2.
//
// A Client owns a copy of the ClientConfig given to New: later changes to the
// caller's struct are not seen, and Config returns a copy. After New only the
// client secret (SetClientSecret) and the issuer public key (SetPubKey)
// change. A Client is safe for concurrent use.
type Client struct {
	mu sync.RWMutex
	// cfg is the client's own copy. Only ClientSecret changes after New,
	// under mu; Provider reads the other fields without it.
	cfg       *ClientConfig
	verifyKey *rsa.PublicKey
}

// New returns a Client for a copy of cfg. A PubKey that is not a PEM-encoded
// RSA public key is an error.
func New(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("client config is nil")
	}
	cfg = cfg.clone()
	p := &Client{
		cfg: cfg,
	}

	if cfg.PubKey != "" {
		key := strings.TrimSpace(cfg.PubKey)
		verifyKey, err := certutil.ParseRSAPublicKeyFromPEM([]byte(key))
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to parse Public Key: %q", key)
		}
		p.verifyKey = verifyKey
	}

	logger.KV(xlog.DEBUG, "sts", cfg.ProviderID, "audience", cfg.Audience, "issuer", cfg.Issuer)

	return p, nil
}

// Config returns a copy of the OAuth2 configuration, with the current client
// secret. Changing the copy does not change the Client.
func (p *Client) Config() *ClientConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg.clone()
}

// PublicKey returns the JWT issuer public key parsed from the PubKey setting
// or given to SetPubKey, or nil. This package does not verify tokens with it;
// pass it to a verifier, for example in jwt.StaticKeySet.PublicKeys.
func (p *Client) PublicKey() *rsa.PublicKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.verifyKey
}

// SetPubKey replaces the JWT issuer public key returned by PublicKey.
// During normal operation, identity provider's public key is read from config on start-up.
func (p *Client) SetPubKey(newPubKey *rsa.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifyKey = newPubKey
}

// SetClientSecret sets the client secret used by later token requests
func (p *Client) SetClientSecret(s string) *Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.ClientSecret = s
	return p
}

// CreateTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST
// body parameters.
func (p *Client) CreateTokenRequest(v url.Values, authStyle oauth2.AuthStyle) (*http.Request, error) {
	return p.CreateTokenRequestWithContext(context.Background(), v, authStyle)
}

// CreateTokenRequestWithContext is like CreateTokenRequest but binds the
// request to ctx so the caller can cancel or time out the token exchange.
func (p *Client) CreateTokenRequestWithContext(ctx context.Context, v url.Values, authStyle oauth2.AuthStyle) (*http.Request, error) {
	p.mu.RLock()
	clientID, clientSecret, tokenURL := p.cfg.ClientID, p.cfg.ClientSecret, p.cfg.TokenURL
	p.mu.RUnlock()

	if authStyle == oauth2.AuthStyleInParams {
		v = cloneURLValues(v)
		v.Set("client_id", clientID)
		v.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authStyle == oauth2.AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	return req, nil
}

func cloneURLValues(v url.Values) url.Values {
	v2 := make(url.Values, len(v))
	for k, vv := range v {
		v2[k] = append([]string(nil), vv...)
	}
	return v2
}
