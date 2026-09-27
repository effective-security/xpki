package csr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/oid"
	"golang.org/x/net/idna"
)

// SAN holds subject alternative names classified by type, as ParseSAN
// returns them. Each list keeps the input order without duplicates; a type
// with no names is nil.
type SAN struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

const (
	// maxDNSNameLength is the longest DNS name in text form (RFC 1035).
	maxDNSNameLength = 253
	// maxDNSLabelLength is the longest DNS label (RFC 1035).
	maxDNSLabelLength = 63
)

// idnaProfile converts internationalized DNS names to A-labels. It maps
// case and applies the bidi rule like idna.Lookup, but allows underscores
// and the wildcard label, which idna.Lookup rejects.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))

// ParseSAN classifies, validates and deduplicates subject alternative names
// (XPKI-059). Each name is trimmed of surrounding whitespace and must not
// be empty. It is then, in this order: a URI when it contains "://" (it
// must parse, have a scheme and be ASCII); an IP address when net.ParseIP
// accepts it (an IPv4 address is kept in its 4-byte form); an email address
// when mail.ParseAddress accepts it (the address part is kept, and it must
// be ASCII); otherwise a DNS name. A DNS name with non-ASCII runes is
// converted to A-labels first (IDNA mapping, which also lowercases it); an
// ASCII name keeps its case. The ASCII form must be at most 253
// characters of labels separated by dots, each label 1 to 63 letters,
// digits, hyphens or underscores that neither starts nor ends with a
// hyphen; a wildcard is allowed only as the whole first label of a name
// with at least two labels; a trailing dot is invalid. A single label such
// as "localhost" is valid.
//
// Duplicates are dropped and the first occurrence is kept: DNS names and
// email addresses compare case-insensitively, IP addresses by value (so
// "::ffff:10.0.0.1" duplicates "10.0.0.1"), URIs by their serialized form.
//
// Every invalid name is reported; the returned error joins them as
// `invalid SAN "name": reason`.
func ParseSAN(names []string) (*SAN, error) {
	san := &SAN{}
	var errs []error
	for _, raw := range names {
		if err := san.add(strings.TrimSpace(raw)); err != nil {
			errs = append(errs, errors.WithMessagef(err, "invalid SAN %q", raw))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return san, nil
}

// ApplySAN replaces the subject alternative names of template with names
// parsed by ParseSAN: DNSNames, EmailAddresses, IPAddresses and URIs are
// replaced (a type with no names becomes nil), and every raw SAN extension
// is removed from ExtraExtensions, keeping the order of the others. A nil
// names leaves template unchanged, so the names of a parsed CSR survive; a
// non-nil empty slice clears them. A nil template is an error. On error
// template is unchanged.
func ApplySAN(template *x509.Certificate, names []string) error {
	if template == nil {
		return errors.New("nil certificate template")
	}
	if names == nil {
		return nil
	}
	san, err := ParseSAN(names)
	if err != nil {
		return err
	}
	san.apply(template)
	return nil
}

// SetSAN is ApplySAN without an error: a name ParseSAN rejects is skipped
// with an error log and the valid names are applied. A nil names leaves
// template unchanged; a non-nil empty slice clears the names.
//
// Deprecated: use ApplySAN, which reports the invalid names.
func SetSAN(template *x509.Certificate, names []string) {
	if template == nil || names == nil {
		return
	}
	san := &SAN{}
	for _, raw := range names {
		if err := san.add(strings.TrimSpace(raw)); err != nil {
			logger.KV(xlog.ERROR, "reason", "skipped_invalid_san", "san", raw, "err", err.Error())
		}
	}
	san.apply(template)
}

// apply sets the names of template to s and drops any raw SAN extension.
func (s *SAN) apply(template *x509.Certificate) {
	template.DNSNames = s.DNSNames
	template.EmailAddresses = s.EmailAddresses
	template.IPAddresses = s.IPAddresses
	template.URIs = s.URIs
	if slices.ContainsFunc(template.ExtraExtensions, isSANExtension) {
		// a copy, since the slice may be shared with the parsed CSR
		template.ExtraExtensions = slices.DeleteFunc(slices.Clone(template.ExtraExtensions), isSANExtension)
	}
}

// applyRequest sets the names of the CSR template to s.
func (s *SAN) applyRequest(template *x509.CertificateRequest) {
	template.DNSNames = s.DNSNames
	template.EmailAddresses = s.EmailAddresses
	template.IPAddresses = s.IPAddresses
	template.URIs = s.URIs
}

func isSANExtension(ext pkix.Extension) bool {
	return ext.Id.Equal(oid.ExtensionSubjectAltName)
}

// Validate checks the names of s with the rules of ParseSAN and drops
// duplicates in place, so names that are already classified, such as the
// names of a parsed CSR, get the same validation as names given as strings
// (XPKI-059). On error s is unchanged. The returned error joins every
// invalid name as `invalid SAN "name": reason`.
func (s *SAN) Validate() error {
	if s == nil {
		return nil
	}
	checked := &SAN{}
	var errs []error
	fail := func(name string, err error) {
		errs = append(errs, errors.WithMessagef(err, "invalid SAN %q", name))
	}
	for _, name := range s.DNSNames {
		if err := checked.addDNS(name); err != nil {
			fail(name, err)
		}
	}
	for _, email := range s.EmailAddresses {
		if err := checked.addEmail(email); err != nil {
			fail(email, err)
		}
	}
	for _, ip := range s.IPAddresses {
		if err := checked.addIP(ip); err != nil {
			fail(ip.String(), err)
		}
	}
	for _, u := range s.URIs {
		if u == nil {
			fail("", errors.New("nil URI"))
			continue
		}
		if err := checked.addURI(u); err != nil {
			fail(u.String(), err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	*s = *checked
	return nil
}

// add classifies one trimmed name and appends it to s unless it is a
// duplicate.
func (s *SAN) add(name string) error {
	if name == "" {
		return errors.New("empty name")
	}
	if strings.Contains(name, "://") {
		u, err := url.Parse(name)
		if err != nil {
			return errors.WithMessage(err, "invalid URI")
		}
		return s.addURI(u)
	}
	if ip := net.ParseIP(name); ip != nil {
		return s.addIP(ip)
	}
	if addr, err := mail.ParseAddress(name); err == nil && addr != nil {
		return s.addEmail(addr.Address)
	}
	return s.addDNS(name)
}

// addURI appends u unless its serialized form is a duplicate. The URI must
// have a scheme (RFC 5280 §4.2.1.6) and serialize to ASCII.
func (s *SAN) addURI(u *url.URL) error {
	if u.Scheme == "" {
		return errors.New("URI has no scheme")
	}
	str := u.String()
	if !isASCII(str) {
		return errors.New("URI is not ASCII")
	}
	if !slices.ContainsFunc(s.URIs, func(x *url.URL) bool { return x.String() == str }) {
		s.URIs = append(s.URIs, u)
	}
	return nil
}

// addIP appends ip, an IPv4 address in its 4-byte form, unless an equal
// address is present.
func (s *SAN) addIP(ip net.IP) error {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return errors.Errorf("invalid IP address length %d", len(ip))
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !slices.ContainsFunc(s.IPAddresses, ip.Equal) {
		s.IPAddresses = append(s.IPAddresses, ip)
	}
	return nil
}

// addEmail appends email unless a case-insensitive duplicate is present.
// It must be a bare ASCII address that mail.ParseAddress accepts (RFC 5322
// addr-spec, as RFC 5280 §4.2.1.6 requires), since a CSR can carry any IA5
// string as an email SAN.
func (s *SAN) addEmail(email string) error {
	if email == "" {
		return errors.New("empty email address")
	}
	if !isASCII(email) {
		return errors.New("email address is not ASCII")
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
		return errors.New("invalid email address")
	}
	if !slices.ContainsFunc(s.EmailAddresses, func(x string) bool { return strings.EqualFold(x, email) }) {
		s.EmailAddresses = append(s.EmailAddresses, email)
	}
	return nil
}

// addDNS validates name with the DNS rules of ParseSAN and appends its
// ASCII form unless a case-insensitive duplicate is present.
func (s *SAN) addDNS(name string) error {
	dns, err := dnsToASCII(name)
	if err != nil {
		return err
	}
	if err := validateDNSName(dns); err != nil {
		return err
	}
	if !slices.ContainsFunc(s.DNSNames, func(x string) bool { return strings.EqualFold(x, dns) }) {
		s.DNSNames = append(s.DNSNames, dns)
	}
	return nil
}

// dnsToASCII returns name unchanged when it is ASCII, else its A-label form.
func dnsToASCII(name string) (string, error) {
	if isASCII(name) {
		return name, nil
	}
	ascii, err := idnaProfile.ToASCII(name)
	if err != nil {
		return "", errors.WithMessage(err, "invalid internationalized DNS name")
	}
	return ascii, nil
}

// validateDNSName checks the ASCII DNS name rules of ParseSAN.
func validateDNSName(name string) error {
	if len(name) > maxDNSNameLength {
		return errors.Errorf("DNS name is longer than %d characters", maxDNSNameLength)
	}
	if strings.HasSuffix(name, ".") {
		return errors.New("DNS name has a trailing dot")
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "*" {
			if i != 0 {
				return errors.New("wildcard is not the first label")
			}
			if len(labels) < 2 {
				return errors.New("wildcard without a domain")
			}
			continue
		}
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// validateDNSLabel checks one non-wildcard label.
func validateDNSLabel(label string) error {
	switch {
	case label == "":
		return errors.New("empty DNS label")
	case len(label) > maxDNSLabelLength:
		return errors.Errorf("DNS label %q is longer than %d characters", label, maxDNSLabelLength)
	case label[0] == '-' || label[len(label)-1] == '-':
		return errors.Errorf("DNS label %q starts or ends with a hyphen", label)
	}
	for i := 0; i < len(label); i++ {
		if !isDNSLabelByte(label[i]) {
			return errors.Errorf("invalid character %q in DNS label %q", label[i], label)
		}
	}
	return nil
}

func isDNSLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '_'
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
