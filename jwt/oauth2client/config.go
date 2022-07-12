package oauth2client

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

// Config provides OAuth2 configuration for supported clients
type Config struct {
	// Clients provides a list of supported clients
	Clients []*ClientConfig
}

// ClientConfig provides OAuth2 configuration
type ClientConfig struct {
	// ProviderID specifies Auth.Provider ID
	ProviderID string `json:"provider_id" yaml:"provider_id"`
	// ClientID specifies client ID
	ClientID string `json:"client_id" yaml:"client_id"`
	// ClientSecret specifies client secret
	ClientSecret string `json:"client_secret" yaml:"client_secret"`
	// Scopes specifies the list of scopes
	Scopes []string `json:"scopes" yaml:"scopes"`
	// ResponseType specifies the response type, default is "code"
	ResponseType string `json:"response_type" yaml:"response_type"`
	// AuthURL specifies auth URL
	AuthURL string `json:"auth_url" yaml:"auth_url"`
	// TokenURL specifies token URL
	TokenURL string `json:"token_url"  yaml:"token_url"`
	// UserinfoURL specifies userinfo URL
	UserinfoURL string `json:"userinfo_url"  yaml:"userinfo_url"`
	// WellknownURL specifies URL for wellknown info
	WellknownURL string `json:"wellknown"  yaml:"wellknown"`
	// RedirectURL specifies redirect URL
	RedirectURL string `json:"redirect_url"  yaml:"redirect_url"`
	// PubKey specifies PEM encoded Public Key of the JWT issuer
	PubKey string `json:"pubkey" yaml:"pubkey"`
	// Audience of JWT token
	Audience string `json:"audience" yaml:"audience"`
	// Issuer of JWT token
	Issuer string `json:"issuer" yaml:"issuer"`
}

// LoadConfig returns configuration loaded from a file
func LoadConfig(file string) (*Config, error) {
	if file == "" {
		return &Config{}, nil
	}

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var config Config
	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(b, &config)
	} else {
		err = yaml.Unmarshal(b, &config)
	}
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to unmarshal %q", file)
	}

	return &config, nil
}

// Load returns new Provider
func Load(cfgfile string) ([]*Client, error) {
	logger.KV(xlog.TRACE, "file", cfgfile)

	cfg, err := LoadConfig(cfgfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	list := make([]*Client, len(cfg.Clients))
	for idx, c := range cfg.Clients {
		list[idx], err = New(c)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return list, nil
}

// LoadClient returns a single `Client` loaded from config
func LoadClient(file string) (*Client, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var config ClientConfig
	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(b, &config)
	} else {
		err = yaml.Unmarshal(b, &config)
	}
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to unmarshal %q", file)
	}
	return New(&config)
}
