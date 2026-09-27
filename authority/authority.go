package authority

import (
	"bytes"
	"crypto"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "authority")

// Authority defines the CA: a registry of issuers and of the profiles that
// are not served by one issuer (wildcard profiles).
//
// An Authority is safe for concurrent use. Lookups read an immutable
// snapshot of the registry; AddIssuer and AddProfile publish a new snapshot
// (XPKI-055). Profiles and Issuers return copies that the caller owns. The
// *CertProfile values are the registered profiles themselves, shared with
// every reader: a profile belongs to the registry once it is added and must
// not be modified afterwards; register a Copy to change one.
type Authority struct {
	// Crypto holds providers for HSM, SoftHSM, KMS, etc.
	crypto *cryptoprov.Crypto

	// registry is the current snapshot; nil is the empty registry.
	registry atomic.Pointer[registry]
	// mu serializes the writers of registry.
	mu sync.Mutex

	RootBundle []byte
	CaBundle   []byte
}

// registry is an immutable snapshot of the issuers and profiles.
type registry struct {
	issuers          map[string]*Issuer // label => Issuer
	issuersByProfile map[string]*Issuer // cert profile => Issuer
	issuersByKeyID   map[string]*Issuer // SKID => Issuer

	// profiles are the profiles of the configuration and those added with
	// AddProfile, including the wildcard profiles that no issuer serves.
	profiles map[string]*CertProfile
}

var emptyRegistry = &registry{}

// cloneMap returns a non-nil copy of m. Snapshots are immutable, so a writer
// clones only the maps it changes and shares the others.
func cloneMap[M ~map[K]V, K comparable, V any](m M) M {
	c := make(M, len(m)+1)
	maps.Copy(c, m)
	return c
}

// load returns the current snapshot.
func (s *Authority) load() *registry {
	if r := s.registry.Load(); r != nil {
		return r
	}
	return emptyRegistry
}

// NewAuthority returns new instance of Authority
func NewAuthority(cfg *Config, crypto *cryptoprov.Crypto) (*Authority, error) {
	if cfg.Authority == nil {
		return nil, errors.New("missing Authority configuration")
	}
	cfg = cfg.Copy()
	ca := &Authority{
		crypto: crypto,
	}
	ca.registry.Store(&registry{
		issuers:          map[string]*Issuer{},
		issuersByProfile: map[string]*Issuer{},
		issuersByKeyID:   map[string]*Issuer{},
		profiles:         cloneMap(cfg.Profiles),
	})
	rootBundle, err := certutil.LoadPEMFiles(cfg.Authority.RootsBundleFiles...)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to load Root bundles")
	}
	ca.RootBundle = rootBundle

	caBundle, err := certutil.LoadPEMFiles(cfg.Authority.CABundleFiles...)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to load CA bundles")
	}
	ca.CaBundle = caBundle

	for _, isscfg := range cfg.Authority.Issuers {
		if isscfg.GetDisabled() {
			logger.KV(xlog.INFO, "reason", "disabled", "issuer", isscfg.Label)
			continue
		}

		ccfg := isscfg.Copy()
		issuer, err := NewIssuerWithBundles(ccfg, crypto, ca.CaBundle, ca.RootBundle)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to create issuer: %q", isscfg.Label)
		}
		err = ca.AddIssuer(issuer)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to add issuer: %q", isscfg.Label)
		}
	}

	return ca, nil
}

// Crypto returns the provider
func (s *Authority) Crypto() *cryptoprov.Crypto {
	return s.crypto
}

// AddProfile adds or replaces the CertProfile named label. The profile must
// not be modified after this call.
func (s *Authority) AddProfile(label string, p *CertProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.load()
	next := *current
	next.profiles = cloneMap(current.profiles)
	next.profiles[label] = p
	s.registry.Store(&next)
}

// Profile returns the CertProfile named label, or nil.
func (s *Authority) Profile(label string) *CertProfile {
	return s.load().profiles[label]
}

// Profiles returns a copy of the profiles map. The caller owns the map;
// the profiles are shared and must not be modified.
func (s *Authority) Profiles() map[string]*CertProfile {
	return cloneMap(s.load().profiles)
}

// AddIssuer adds issuer to the Authority and registers its profiles, except
// the wildcard ones. It is an error, and nothing is added, when an issuer
// with the same label is registered, when one of the profiles is already
// registered by an issuer (the error names the profile and that issuer), or
// when one of the profiles is nil. An issuer with the same subject key id as
// a registered one replaces it in the key id lookup only.
func (s *Authority) AddIssuer(issuer *Issuer) error {
	if issuer == nil {
		return errors.New("nil issuer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.load()

	if _, ok := current.issuers[issuer.Label()]; ok {
		return errors.Errorf("issuer %q is already registered", issuer.Label())
	}
	profiles := issuer.Profiles()
	served := make([]string, 0, len(profiles))
	for _, name := range slices.Sorted(maps.Keys(profiles)) {
		profile := profiles[name]
		if profile == nil {
			return errors.Errorf("profile %q of issuer %q is nil", name, issuer.Label())
		}
		if profile.IssuerLabel == wildcardIssuer {
			continue
		}
		// Maybe this is a redundand check, after config loaded and Validate() call
		if is := current.issuersByProfile[name]; is != nil {
			return errors.Errorf("profile %q is already registered by %q issuer", name, is.Label())
		}
		served = append(served, name)
	}

	next := &registry{
		issuers:          cloneMap(current.issuers),
		issuersByProfile: cloneMap(current.issuersByProfile),
		issuersByKeyID:   cloneMap(current.issuersByKeyID),
		profiles:         current.profiles,
	}
	next.issuers[issuer.Label()] = issuer
	next.issuersByKeyID[issuer.SubjectKID()] = issuer
	for _, name := range served {
		next.issuersByProfile[name] = issuer
	}
	s.registry.Store(next)
	return nil
}

// GetIssuerByKeyID by IKID
func (s *Authority) GetIssuerByKeyID(ikid string) (*Issuer, error) {
	if issuer, ok := s.load().issuersByKeyID[ikid]; ok {
		return issuer, nil
	}
	return nil, errors.Errorf("issuer not found: %s", ikid)
}

// GetIssuerByLabel by label
func (s *Authority) GetIssuerByLabel(label string) (*Issuer, error) {
	if issuer, ok := s.load().issuers[label]; ok {
		return issuer, nil
	}
	return nil, errors.Errorf("issuer not found: %s", label)
}

// GetIssuerByProfile by profile
func (s *Authority) GetIssuerByProfile(profile string) (*Issuer, error) {
	if issuer, ok := s.load().issuersByProfile[profile]; ok {
		return issuer, nil
	}
	return nil, errors.Errorf("issuer not found for profile: %s", profile)
}

// GetIssuerByKeyHash returns matching Issuer by key hash
func (s *Authority) GetIssuerByKeyHash(alg crypto.Hash, val []byte) (*Issuer, error) {
	for _, iss := range s.load().issuers {
		if bytes.Equal(iss.keyHash[alg], val) {
			return iss, nil
		}
	}

	return nil, errors.New("issuer not found")
}

// GetIssuerByNameHash returns matching Issuer by name hash
func (s *Authority) GetIssuerByNameHash(alg crypto.Hash, val []byte) (*Issuer, error) {
	for _, iss := range s.load().issuers {
		if bytes.Equal(iss.nameHash[alg], val) {
			return iss, nil
		}
	}

	return nil, errors.New("issuer not found")
}

// Issuers returns the issuers sorted by label.
func (s *Authority) Issuers() []*Issuer {
	current := s.load()
	list := make([]*Issuer, 0, len(current.issuers))
	for _, ca := range current.issuers {
		list = append(list, ca)
	}
	slices.SortFunc(list, func(a, b *Issuer) int {
		return strings.Compare(a.Label(), b.Label())
	})
	return list
}
