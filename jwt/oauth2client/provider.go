package oauth2client

// Provider of OAuth2 clients
type Provider struct {
	clients map[string]*Client
	domains map[string]*Client
}

// LoadProvider returns Provider
func LoadProvider(location string) (*Provider, error) {
	p := &Provider{
		clients: make(map[string]*Client),
		domains: make(map[string]*Client),
	}

	list, err := Load(location)
	if err != nil {
		return nil, err
	}

	for _, cl := range list {
		p.clients[cl.cfg.ProviderID] = cl

		for _, domain := range cl.cfg.Domains {
			p.domains[domain] = cl
		}
	}

	return p, nil
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
func (p *Provider) ClientForDomain(domain string) *Client {
	return p.domains[domain]
}

// ClientNames returns list of supported clients
func (p *Provider) ClientNames() []string {
	list := make([]string, 0, len(p.clients))
	for k := range p.clients {
		list = append(list, k)
	}

	return list
}
