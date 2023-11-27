package oauth2client

import (
	"crypto/rsa"
	"net/http"
	"net/url"
	"strings"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki/jwt", "oauth2client")

// Client of OAuth2
type Client struct {
	cfg       *ClientConfig
	verifyKey *rsa.PublicKey // TODO: crypto.PublicKey
}

// New returns new Provider
func New(cfg *ClientConfig) (*Client, error) {
	// var err error
	// cfg.ClientID, err = fileutil.LoadConfigWithSchema(cfg.ClientID)
	// if err != nil {
	// 	return nil, err
	// }
	// cfg.ClientSecret, err = fileutil.LoadConfigWithSchema(cfg.ClientSecret)
	// if err != nil {
	// 	return nil, err
	// }
	// cfg.AuthURL, err = fileutil.LoadConfigWithSchema(cfg.AuthURL)
	// if err != nil {
	// 	return nil, err
	// }
	// cfg.TokenURL, err = fileutil.LoadConfigWithSchema(cfg.TokenURL)
	// if err != nil {
	// 	return nil, err
	// }
	// cfg.UserinfoURL, err = fileutil.LoadConfigWithSchema(cfg.UserinfoURL)
	// if err != nil {
	// 	return nil, err
	// }
	// cfg.RedirectURL, err = fileutil.LoadConfigWithSchema(cfg.RedirectURL)
	// if err != nil {
	// 	return nil, err
	// }

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

// Config returns OAuth2 configuration
func (p *Client) Config() *ClientConfig {
	return p.cfg
}

// SetPubKey replaces the OAuth public signing key loaded from configuration
// During normal operation, identity provider's public key is read from config on start-up.
func (p *Client) SetPubKey(newPubKey *rsa.PublicKey) {
	p.verifyKey = newPubKey
}

// SetClientSecret sets Client Secret
func (p *Client) SetClientSecret(s string) *Client {
	p.cfg.ClientSecret = s
	return p
}

// CreateTokenRequest returns a new *http.Request to retrieve a new token
// from tokenURL using the provided clientID, clientSecret, and POST
// body parameters.
func (p *Client) CreateTokenRequest(v url.Values, authStyle oauth2.AuthStyle) (*http.Request, error) {
	if authStyle == oauth2.AuthStyleInParams {
		v = cloneURLValues(v)
		v.Set("client_id", p.cfg.ClientID)
		v.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, p.cfg.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authStyle == oauth2.AuthStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
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
