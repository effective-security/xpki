package oauth2client

import (
	"github.com/effective-security/xpki/x/fileutil"
)

// Config provides OAuth2 configuration for supported clients
type Config struct {
	// Clients provides a list of supported clients
	Clients []*ClientConfig `json:"clients" yaml:"clients"`
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
	// JwksURL specifies JWKS URL
	JwksURL string `json:"jwks_url" yaml:"jwks_url"`
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
	// Prompt parameter, such as `consent`
	Prompt string `json:"prompt" yaml:"prompt"`
	// Audience of JWT token
	Audience string `json:"audience" yaml:"audience"`
	// Issuer of JWT token
	Issuer string `json:"issuer" yaml:"issuer"`
	// IDPParam specifies the IDP parameters
	IDPParam *IDPParam `json:"idp_param" yaml:"idp_param"`
	// Domains specifies the list of domains to filter by
	Domains []string `json:"domains" yaml:"domains"`
}

// IDPParam is a struct for IDP parameter
type IDPParam struct {
	// Name specifies the name of the IDP parameter: idpuser.email|identity_provider
	Name string `json:"name" yaml:"name"`
	// Value specifies the value the IDP parameter: email|domain|{value}
	Value string `json:"value" yaml:"value"`
}

// LoadConfig returns configuration loaded from a file
func LoadConfig(file string) (*Config, error) {
	config := new(Config)
	if file == "" {
		return config, nil
	}
	err := fileutil.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// Load returns new Provider
func Load(cfgfile string) ([]*Client, error) {
	cfg, err := LoadConfig(cfgfile)
	if err != nil {
		return nil, err
	}

	list := make([]*Client, len(cfg.Clients))
	for idx, c := range cfg.Clients {
		list[idx], err = New(c)
		if err != nil {
			return nil, err
		}
	}

	return list, nil
}

// LoadClient returns a single `Client` loaded from config
func LoadClient(file string) (*Client, error) {
	config := new(ClientConfig)
	err := fileutil.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}
	return New(config)
}
