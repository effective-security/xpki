package oauth2client

import (
	"github.com/pkg/errors"
)

// Provider of OAuth2 clients
type Provider struct {
	clients map[string]*Client
}

// LoadProvider returns Provider
func LoadProvider(location string) (*Provider, error) {
	p := &Provider{
		clients: make(map[string]*Client),
	}

	list, err := Load(location)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	for _, cl := range list {
		p.clients[cl.cfg.ProviderID] = cl
	}

	return p, nil
}

// Client returns Client by provider
func (p *Provider) Client(id string) *Client {
	return p.clients[id]
}
