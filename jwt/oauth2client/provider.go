package oauth2client

import (
	"maps"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/errors"
)

// registry is an immutable snapshot of the Provider indexes; RegisterClient
// publishes a new one, so lookups never see a partial registration.
type registry struct {
	clients map[string]*Client
	domains map[string]*Client
	emails  map[string]*Client
}

var emptyRegistry = &registry{}

// clone returns a registry with copies of the indexes, ready to be modified
func (r *registry) clone() *registry {
	return &registry{
		clients: cloneIndex(r.clients),
		domains: cloneIndex(r.domains),
		emails:  cloneIndex(r.emails),
	}
}

func cloneIndex(index map[string]*Client) map[string]*Client {
	if index == nil {
		return map[string]*Client{}
	}
	return maps.Clone(index)
}

// Provider is a registry of OAuth2 clients looked up by provider id, domain
// or email. It is safe for concurrent use: a registration is published to
// every index at once, and a rejected one leaves the registry unchanged.
// The zero value is an empty registry.
type Provider struct {
	mu  sync.Mutex // serializes RegisterClient
	reg atomic.Pointer[registry]
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
	p := &Provider{}

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

func (p *Provider) load() *registry {
	if r := p.reg.Load(); r != nil {
		return r
	}
	return emptyRegistry
}

// RegisterClient registers a new client under its provider id, domains and
// emails. Without override, a provider id, domain or email that is already
// registered is an error and nothing is registered. With override, the
// previous client of the same provider id is removed from every index, and
// a domain or email registered by another client is taken over.
func (p *Provider) RegisterClient(c *ClientConfig, override bool) error {
	cl, err := New(c)
	if err != nil {
		return err
	}
	cfg := cl.cfg

	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.load()

	if !override {
		for _, email := range cfg.Emails {
			if cur.emails[email] != nil {
				return errors.Errorf("OAuth client email already registered: %s", email)
			}
		}
		for _, domain := range cfg.Domains {
			if cur.domains[domain] != nil {
				return errors.Errorf("OAuth client domain already registered: %s", domain)
			}
		}
		if cur.clients[cfg.ProviderID] != nil {
			return errors.Errorf("OAuth provider already registered: %s", cfg.ProviderID)
		}
	}

	next := cur.clone()
	if old := next.clients[cfg.ProviderID]; old != nil {
		// only reached with override: unpublish the previous registration
		maps.DeleteFunc(next.emails, func(_ string, c *Client) bool { return c == old })
		maps.DeleteFunc(next.domains, func(_ string, c *Client) bool { return c == old })
	}
	for _, email := range cfg.Emails {
		next.emails[email] = cl
	}
	for _, domain := range cfg.Domains {
		next.domains[domain] = cl
	}
	next.clients[cfg.ProviderID] = cl
	p.reg.Store(next)
	return nil
}

// Client returns Client by provider
func (p *Provider) Client(provider string) *Client {
	prov := p.load().clients[provider]
	if prov != nil && len(prov.cfg.Domains) > 0 {
		return nil
	}
	return prov
}

// ClientForProvider returns Client by provider
func (p *Provider) ClientForProvider(provider string) *Client {
	return p.load().clients[provider]
}

// ClientForDomain returns Client by domain
func (p *Provider) ClientForDomain(domain string) *Client {
	return p.load().domains[domain]
}

// ClientForEmail returns Client by email, falling back to the client
// configured for the email's domain. It returns nil for a value that is
// not an address of the form local@domain.
func (p *Provider) ClientForEmail(email string) *Client {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return nil
	}
	r := p.load()
	if c := r.emails[email]; c != nil {
		return c
	}
	return r.domains[domain]
}

// ClientNames returns list of supported clients
func (p *Provider) ClientNames() []string {
	r := p.load()
	list := make([]string, 0, len(r.clients))
	for name, c := range r.clients {
		if len(c.cfg.Domains) == 0 {
			list = append(list, name)
		}
	}

	return list
}

// Domains returns list of supported domains
func (p *Provider) Domains() []string {
	r := p.load()
	list := make([]string, 0, len(r.domains))
	for name := range r.domains {
		list = append(list, name)
	}

	return list
}

// Emails returns list of configured emails
func (p *Provider) Emails() []string {
	r := p.load()
	list := make([]string, 0, len(r.emails))
	for name := range r.emails {
		list = append(list, name)
	}

	return list
}
