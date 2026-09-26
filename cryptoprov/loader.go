package cryptoprov

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// ProviderLoader is interface for loading provider by manufacturer
type ProviderLoader func(cfg TokenConfig) (Provider, error)

var (
	lockLoaders sync.RWMutex
	loaders     = make(map[string]ProviderLoader)
)

// Register provider loader by manufacturer
func Register(manufacturer string, loader ProviderLoader) error {
	lockLoaders.Lock()
	defer lockLoaders.Unlock()

	if _, ok := loaders[manufacturer]; ok {
		return errors.Errorf("already registered: %s", manufacturer)
	}

	loaders[manufacturer] = loader

	return nil
}

// Unregister provider loader by manufacturer
func Unregister(manufacturer string) (ProviderLoader, error) {
	lockLoaders.Lock()
	defer lockLoaders.Unlock()

	if loader, ok := loaders[manufacturer]; ok {
		delete(loaders, manufacturer)
		return loader, nil
	}

	return nil, errors.Errorf("not registered: %s", manufacturer)
}

// Registered returns registered providers
func Registered() []string {
	lockLoaders.RLock()
	defer lockLoaders.RUnlock()

	list := []string{}
	for m := range loaders {
		list = append(list, m)
	}
	return list
}

// LoadProvider load a single provider
func LoadProvider(configLocation string) (Provider, error) {
	tc, err := LoadTokenConfig(configLocation)
	if err != nil {
		return nil, err
	}

	manufacturer := tc.Manufacturer()
	lockLoaders.RLock()
	loader, ok := loaders[manufacturer]
	lockLoaders.RUnlock()
	if !ok {
		return nil, errors.Errorf("provider not registered: %s", manufacturer)
	}

	prov, err := loader(tc)
	if err != nil {
		return nil, err
	}

	return prov, nil
}

// Load returns Crypto with loaded providers from the given config locations.
// Each config must name a different manufacturer and model than the others
// (ErrDuplicateProvider). On error, Load closes the providers it already
// loaded that implement Close() error.
func Load(defaultConfig string, providersConfigs []string) (c *Crypto, err error) {
	var loaded []Provider
	defer func() {
		if err != nil {
			closeProviders(loaded)
		}
	}()

	p, err := LoadProvider(defaultConfig)
	if err != nil {
		return nil, err
	}
	loaded = append(loaded, p)

	// ByManufacturer finds the default provider without adding it (XPKI-113)
	c, err = New(p, nil)
	if err != nil {
		return nil, err
	}
	for _, configLocation := range providersConfigs {
		p, err = LoadProvider(configLocation)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, p)
		if err = c.Add(p); err != nil {
			return nil, errors.WithMessagef(err, "unable to add provider from %s", configLocation)
		}
	}
	return c, nil
}

// closeProviders closes the providers that implement Close() error, such
// as crypto11.PKCS11Lib, and logs the errors, since the caller is already
// returning one.
func closeProviders(providers []Provider) {
	for _, p := range providers {
		if isNilProvider(p) {
			continue
		}
		if closer, ok := p.(interface{ Close() error }); ok {
			if cerr := closer.Close(); cerr != nil {
				logger.KV(xlog.ERROR,
					"reason", "close",
					"manufacturer", p.Manufacturer(),
					"model", p.Model(),
					"err", cerr.Error(),
				)
			}
		}
	}
}
