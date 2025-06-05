package oauth2client

import (
	"strings"

	"github.com/cockroachdb/errors"
)

// Provider of OAuth2 clients
type Provider struct {
	clients map[string]*Client
	domains map[string]*Client
	emails  map[string]*Client
}

// LoadProvider returns Provider
func LoadProvider(location string) (*Provider, error) {
	cfg, err := LoadConfig(location)
	if err != nil {
		return nil, err
	}
	return NewProvider(cfg)
}

// NewProvider returns Provider
func NewProvider(cfg *Config) (*Provider, error) {
	p := &Provider{
		clients: make(map[string]*Client),
		domains: make(map[string]*Client),
		emails:  make(map[string]*Client),
	}

	for _, c := range cfg.Clients {
		if c.Disabled {
			continue
		}
		err := p.RegisterClient(c, false)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

// RegisterClient registers new client
func (p *Provider) RegisterClient(c *ClientConfig, override bool) error {
	cl, err := New(c)
	if err != nil {
		return err
	}
	for _, email := range cl.cfg.Emails {
		if !override && p.emails[email] != nil {
			return errors.Errorf("OAuth client email already registered: %s", email)
		}
		p.emails[email] = cl
	}
	for _, domain := range cl.cfg.Domains {
		if !override && p.domains[domain] != nil {
			return errors.Errorf("OAuth client domain already registered: %s", domain)
		}
		p.domains[domain] = cl
	}
	if !override && p.clients[cl.cfg.ProviderID] != nil {
		return errors.Errorf("OAuth provider already registered: %s", cl.cfg.ProviderID)
	}
	p.clients[cl.cfg.ProviderID] = cl
	return nil
}

// Client returns Client by provider
func (p *Provider) Client(provider string) *Client {
	prov := p.clients[provider]
	if prov != nil && len(prov.cfg.Domains) > 0 {
		return nil
	}
	return prov
}

// ClientForDomain returns Client by domain
func (p *Provider) ClientForProvider(provider string) *Client {
	return p.clients[provider]
}

// ClientForDomain returns Client by domain
func (p *Provider) ClientForDomain(domain string) *Client {
	return p.domains[domain]
}

// ClientForEmail returns Client by email
func (p *Provider) ClientForEmail(email string) *Client {
	c := p.emails[email]
	if c != nil {
		return c
	}
	parts := strings.Split(email, "@")
	domain := parts[len(parts)-1]
	return p.domains[domain]
}

// ClientNames returns list of supported clients
func (p *Provider) ClientNames() []string {
	list := make([]string, 0, len(p.clients))
	for name, c := range p.clients {
		if len(c.cfg.Domains) == 0 {
			list = append(list, name)
		}
	}

	return list
}

// Domains returns list of supported domains
func (p *Provider) Domains() []string {
	list := make([]string, 0, len(p.domains))
	for name := range p.domains {
		list = append(list, name)
	}

	return list
}

// Emails returns list of configured emails
func (p *Provider) Emails() []string {
	list := make([]string, 0, len(p.emails))
	for name := range p.emails {
		list = append(list, name)
	}

	return list
}
