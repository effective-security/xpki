package authority

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/jinzhu/copier"
	"gopkg.in/yaml.v3"
)

var (
	// DefaultCRLRenewal specifies default duration for CRL renewal
	DefaultCRLRenewal = 12 * time.Hour // 12 hours
	// DefaultCRLExpiry specifies default duration for CRL expiry
	DefaultCRLExpiry = 2 * 24 * time.Hour // 2 days
	// DefaultOCSPExpiry specifies default for OCSP expiry
	DefaultOCSPExpiry = 8 * time.Hour // 8 hours
)

// Config provides configuration for Certification Authority
type Config struct {
	Authority *CAConfig               `json:"authority,omitempty" yaml:"authority,omitempty"`
	Profiles  map[string]*CertProfile `json:"profiles" yaml:"profiles"`
}

// CAConfig contains configuration info for CA
type CAConfig struct {
	// Issuers specifies the list of issuing authorities.
	Issuers []IssuerConfig `json:"issuers,omitempty" yaml:"issuers,omitempty"`

	// RootsBundleFiles specifies locations of the Root bundle files
	RootsBundleFiles []string `json:"root_bundles,omitempty" yaml:"root_bundles,omitempty"`

	// CABundleFiles specifies locations of the CA bundle files
	CABundleFiles []string `json:"ca_bundles,omitempty" yaml:"ca_bundles,omitempty"`
}

// IssuerConfig contains configuration info for the issuing certificate
type IssuerConfig struct {
	// Disabled specifies if the certificate disabled to use
	Disabled *bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// Label specifies Issuer's label
	Label string `json:"label,omitempty" yaml:"label,omitempty"`

	// Type specifies type: tls|codesign|timestamp|ocsp|spiffe|trusty
	Type string

	// CertFile specifies location of the cert
	CertFile string `json:"cert,omitempty" yaml:"cert,omitempty"`

	// KeyFile specifies location of the key
	KeyFile string `json:"key,omitempty" yaml:"key,omitempty"`

	// CABundleFile specifies location of the CA bundle file
	CABundleFile string `json:"ca_bundle,omitempty" yaml:"ca_bundle,omitempty"`

	// RootBundleFile specifies location of the Root CA file
	RootBundleFile string `json:"root_bundle,omitempty" yaml:"root_bundle,omitempty"`

	// OmitDisabledExtensions specifies to not fail a request,
	// but omit not allowed extentions
	OmitDisabledExtensions bool `json:"omit_disabled_extensions,omitempty" yaml:"omit_disabled_extensions,omitempty"`

	// AIA specifies AIA configuration
	AIA *AIAConfig `json:"aia,omitempty" yaml:"aia,omitempty"`

	// AllowedProfiles if populated, allows only specified profiles
	AllowedProfiles []string `json:"allowed_profiles" yaml:"allowed_profiles"`

	// Profiles are populated after loading
	Profiles map[string]*CertProfile `json:"-" yaml:"-"`
}

// AIAConfig contains AIA configuration info
type AIAConfig struct {
	// AiaURL specifies a template for AIA URL.
	// The ${ISSUER_ID} variable will be replaced with a Subject Key Identifier of the issuer.
	AiaURL string `json:"issuer_url" yaml:"issuer_url"`

	// OcspURL specifies a template for OCSP URL.
	// The ${ISSUER_ID} variable will be replaced with a Subject Key Identifier of the issuer.
	OcspURL string `json:"ocsp_url" yaml:"ocsp_url"`

	// DefaultOcspURL specifies a template for CRL URL.
	// The ${ISSUER_ID} variable will be replaced with a Subject Key Identifier of the issuer.
	CrlURL string `json:"crl_url" yaml:"crl_url"`

	// CRLExpiry specifies value in 72h format for duration of CRL next update time
	CRLExpiry time.Duration `json:"crl_expiry,omitempty" yaml:"crl_expiry,omitempty"`

	// OCSPExpiry specifies value in 8h format for duration of OCSP next update time
	OCSPExpiry time.Duration `json:"ocsp_expiry,omitempty" yaml:"ocsp_expiry,omitempty"`

	// CRLRenewal specifies value in 8h format for duration of CRL renewal before next update time
	CRLRenewal time.Duration `json:"crl_renewal,omitempty" yaml:"crl_renewal,omitempty"`

	// DelegatedOCSPProfile specifies to use delegated OCSP responder
	DelegatedOCSPProfile string `json:"delegated_ocsp_profile,omitempty" yaml:"delegated_ocsp_profile,omitempty"`
}

// Copy returns new copy
func (c *Config) Copy() *Config {
	d := new(Config)
	_ = copier.Copy(d, c)
	return d
}

// Copy returns new copy
func (c *IssuerConfig) Copy() *IssuerConfig {
	d := new(IssuerConfig)
	_ = copier.Copy(d, c)
	return d
}

// Copy returns new copy
func (c *AIAConfig) Copy() *AIAConfig {
	return &AIAConfig{
		c.AiaURL,
		c.OcspURL,
		c.CrlURL,
		c.CRLExpiry,
		c.OCSPExpiry,
		c.CRLRenewal,
		c.DelegatedOCSPProfile,
	}
}

// GetDisabled specifies if the certificate disabled to use
func (c *IssuerConfig) GetDisabled() bool {
	return c.Disabled != nil && *c.Disabled
}

// GetCRLExpiry specifies value in 72h format for duration of CRL next update time
func (c *AIAConfig) GetCRLExpiry() time.Duration {
	if c != nil && c.CRLExpiry > 0 {
		return c.CRLExpiry
	}
	return DefaultCRLExpiry
}

// GetOCSPExpiry specifies value in 8h format for duration of OCSP next update time
func (c *AIAConfig) GetOCSPExpiry() time.Duration {
	if c != nil && c.OCSPExpiry > 0 {
		return c.OCSPExpiry
	}
	return DefaultOCSPExpiry
}

// GetCRLRenewal specifies value in 8h format for duration of CRL renewal before next update time
func (c *AIAConfig) GetCRLRenewal() time.Duration {
	if c != nil && c.CRLRenewal > 0 {
		return c.CRLRenewal
	}
	return DefaultCRLRenewal
}

// CertProfile provides certificate profile
type CertProfile struct {
	IssuerLabel string `json:"issuer_label" yaml:"issuer_label"`
	Description string `json:"description" yaml:"description"`

	// Usage provides a list key usages
	Usage []string `json:"usages" yaml:"usages"`

	CAConstraint CAConstraint `json:"ca_constraint" yaml:"ca_constraint"`
	OCSPNoCheck  bool         `json:"ocsp_no_check" yaml:"ocsp_no_check"`

	Expiry   csr.Duration `json:"expiry" yaml:"expiry"`
	Backdate csr.Duration `json:"backdate" yaml:"backdate"`

	Extensions []csr.X509Extension `json:"extensions" yaml:"extensions"`

	AllowedExtensions []csr.OID `json:"allowed_extensions" yaml:"allowed_extensions"`

	// AllowedNames specifies a RegExp to check for allowed names.
	// If not provided, then all values are allowed
	AllowedNames string `json:"allowed_names" yaml:"allowed_names"`

	// AllowedDNS specifies a RegExp to check for allowed DNS.
	// If not provided, then all values are allowed
	AllowedDNS string `json:"allowed_dns" yaml:"allowed_dns"`

	// AllowedEmail specifies a RegExp to check for allowed email.
	// If not provided, then all values are allowed
	AllowedEmail string `json:"allowed_email" yaml:"allowed_email"`

	// AllowedURI specifies a RegExp to check for allowed URI.
	// If not provided, then all values are allowed
	AllowedURI string `json:"allowed_uri" yaml:"allowed_uri"`

	// AllowedFields provides booleans for fields in the CSR.
	// If a AllowedFields is not present in a CertProfile,
	// all of these fields may be copied from the CSR into the signed certificate.
	// If a AllowedFields *is* present in a CertProfile,
	// only those fields with a `true` value in the AllowedFields may
	// be copied from the CSR to the signed certificate.
	// Note that some of these fields, like Subject, can be provided or
	// partially provided through the API.
	// Since API clients are expected to be trusted, but CSRs are not, fields
	// provided through the API are not subject to validation through this
	// mechanism.
	AllowedCSRFields *csr.AllowedFields `json:"allowed_fields" yaml:"allowed_fields"`

	Policies []csr.CertificatePolicy `json:"policies" yaml:"policies"`
	// PoliciesCritical specifies to mark Policies as Critical extension
	PoliciesCritical bool `json:"policies_critical" yaml:"policies_critical"`

	AllowedRoles []string `json:"allowed_roles" yaml:"allowed_roles"`
	DeniedRoles  []string `json:"denied_roles" yaml:"denied_roles"`

	AllowedNamesRegex *regexp.Regexp `json:"-" yaml:"-"`
	AllowedDNSRegex   *regexp.Regexp `json:"-" yaml:"-"`
	AllowedEmailRegex *regexp.Regexp `json:"-" yaml:"-"`
	AllowedURIRegex   *regexp.Regexp `json:"-" yaml:"-"`
}

// CAConstraint specifies various CA constraints on the signed certificate.
// CAConstraint would verify against (and override) the CA
// extensions in the given CSR.
type CAConstraint struct {
	IsCA       bool `json:"is_ca" yaml:"is_ca"`
	MaxPathLen int  `json:"max_path_len" yaml:"max_path_len"`
}

// Copy returns new copy
func (p *CertProfile) Copy() *CertProfile {
	d := new(CertProfile)
	_ = copier.Copy(d, p)
	return d
}

// AllowedExtensionsStrings returns slice of strings
func (p *CertProfile) AllowedExtensionsStrings() []string {
	list := make([]string, len(p.AllowedExtensions))
	for i, o := range p.AllowedExtensions {
		list[i] = o.String()
	}
	return list
}

// IsAllowed returns true, if a role is allowed to request this profile
func (p *CertProfile) IsAllowed(role string) bool {
	if len(p.DeniedRoles) > 0 &&
		(slices.ContainsString(p.DeniedRoles, role) || slices.ContainsString(p.DeniedRoles, "*")) {
		return false
	}
	if len(p.AllowedRoles) > 0 &&
		(slices.ContainsString(p.AllowedRoles, role) || slices.ContainsString(p.AllowedRoles, "*")) {
		return true
	}
	return true
}

// LoadConfig loads the configuration file stored at the path
// and returns the configuration.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("invalid path")
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read configuration file")
	}

	var cfg = new(Config)
	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(body, cfg)
	} else {
		err = yaml.Unmarshal(body, cfg)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal configuration")
	}

	if len(cfg.Profiles) == 0 {
		return nil, errors.New("no \"profiles\" configuration present")
	}

	if cfg.Authority != nil {
		issuers := map[string]*IssuerConfig{}
		count := len(cfg.Authority.Issuers)
		for i := range cfg.Authority.Issuers {
			iss := &cfg.Authority.Issuers[i]
			if issuers[iss.Label] != nil {
				return nil, errors.Errorf("duplicate issuer configuration found: %s", iss.Label)
			}
			issuers[iss.Label] = iss

			iss.Profiles = make(map[string]*CertProfile)
			for name, profile := range cfg.Profiles {
				if profile.IssuerLabel == "" {
					if count == 1 {
						profile.IssuerLabel = cfg.Authority.Issuers[0].Label
					} else if count > 1 {
						return nil, errors.Errorf("profile has no issuer label: %s", name)
					}
				}

				if profile.IssuerLabel == iss.Label ||
					(profile.IssuerLabel == "*" && slices.ContainsString(iss.AllowedProfiles, name)) {
					iss.Profiles[name] = profile
				}
			}
		}
	}

	if err = cfg.Validate(); err != nil {
		return nil, errors.WithMessage(err, "invalid configuration")
	}

	return cfg, nil
}

// DefaultCertProfile returns default CertProfile
func (c *Config) DefaultCertProfile() *CertProfile {
	return c.Profiles["default"]
}

// Validate returns an error if the profile is invalid
func (p *CertProfile) Validate() error {
	if p.Expiry == 0 {
		return errors.New("no expiry set")
	}

	if len(p.Usage) == 0 && p.FindExtension(oid.ExtensionKeyUsage) == nil {
		return errors.New("no usages specified")
	} else if _, _, unk := p.Usages(); len(unk) > 0 {
		return errors.Errorf("unknown usage: %s", strings.Join(unk, ","))
	}

	for _, policy := range p.Policies {
		for _, qualifier := range policy.Qualifiers {
			if qualifier.Type != "" &&
				qualifier.Type != csr.UserNoticeQualifierType &&
				qualifier.Type != csr.CpsQualifierType {
				return errors.New("invalid policy qualifier type: " + qualifier.Type)
			}
		}
	}

	if p.AllowedNames != "" && p.AllowedNamesRegex == nil {
		rule, err := regexp.Compile(p.AllowedNames)
		if err != nil {
			return errors.Wrap(err, "failed to compile AllowedNames")
		}
		p.AllowedNamesRegex = rule
	}
	if p.AllowedDNS != "" && p.AllowedDNSRegex == nil {
		rule, err := regexp.Compile(p.AllowedDNS)
		if err != nil {
			return errors.Wrap(err, "failed to compile AllowedDNS")
		}
		p.AllowedDNSRegex = rule
	}
	if p.AllowedEmail != "" && p.AllowedEmailRegex == nil {
		rule, err := regexp.Compile(p.AllowedEmail)
		if err != nil {
			return errors.Wrap(err, "failed to compile AllowedEmail")
		}
		p.AllowedEmailRegex = rule
	}
	if p.AllowedURI != "" && p.AllowedURIRegex == nil {
		rule, err := regexp.Compile(p.AllowedURI)
		if err != nil {
			return errors.Wrap(err, "failed to compile AllowedURI")
		}
		p.AllowedURIRegex = rule
	}

	return nil
}

// IsAllowedExtention returns true of the extension is allowed
func (p *CertProfile) IsAllowedExtention(oid csr.OID) bool {
	if len(p.AllowedExtensions) == 0 {
		// if non specified, then all allowed
		return true
	}
	for _, allowed := range p.AllowedExtensions {
		if allowed.Equal(oid) {
			return true
		}
	}
	return false
}

// FindExtension returns extension, or nil
func (p *CertProfile) FindExtension(oid asn1.ObjectIdentifier) *csr.X509Extension {
	other := csr.OID(oid)
	for idx, e := range p.Extensions {
		if e.ID.Equal(other) {
			return &p.Extensions[idx]
		}
	}
	return nil
}

// Validate returns an error if the configuration is invalid
func (c *Config) Validate() error {
	var err error

	issuers := map[string]bool{}
	count := 0
	if c.Authority != nil {
		count = len(c.Authority.Issuers)
		for i := range c.Authority.Issuers {
			iss := &c.Authority.Issuers[i]
			issuers[iss.Label] = true
		}
	}

	for name, profile := range c.Profiles {
		err = profile.Validate()
		if err != nil {
			return errors.WithMessagef(err, "invalid %s profile", name)
		}
		if count > 0 {
			if profile.IssuerLabel == "" {
				return errors.Errorf("profile has no issuer label: %s", name)
			}
			if profile.IssuerLabel != "*" && !issuers[profile.IssuerLabel] {
				return errors.Errorf("%q issuer not found for %q profile", profile.IssuerLabel, name)
			}
		}
	}

	return nil
}

// Usages parses the list of key uses in the profile, translating them
// to a list of X.509 key usages and extended key usages.
// The unknown uses are collected into a slice that is also returned.
func (p *CertProfile) Usages() (ku x509.KeyUsage, eku []x509.ExtKeyUsage, unk []string) {
	for _, keyUse := range p.Usage {
		if kuse, ok := oid.KeyUsage[keyUse]; ok {
			ku |= kuse
		} else if ekuse, ok := oid.ExtKeyUsage[keyUse]; ok {
			eku = append(eku, ekuse)
		} else {
			unk = append(unk, keyUse)
		}
	}
	return
}
