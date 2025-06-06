package certutil

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// BundleStatus is designated for various status reporting.
type BundleStatus struct {
	// A list of SKIs of expiring certificates
	ExpiringSKIs []string `json:"expiring_SKIs"`
	// A list of untrusted root store names
	Untrusted []string `json:"untrusted_root_stores"`
	// A list of human readable warning messages based on the bundle status.
	Messages []string `json:"messages"`

	Code int `json:"code"`
}

// IsExpiring returns true if bundle is expiring in less than 30 days
func (b *BundleStatus) IsExpiring() bool {
	return len(b.ExpiringSKIs) > 0
}

// IsUntrusted returns true if the cert's issuers are not trusted
func (b *BundleStatus) IsUntrusted() bool {
	return len(b.Untrusted) > 0
}

// A Bundle contains a certificate and its trust chain. It is intended
// to store the most widely applicable chain, with shortness an
// explicit goal.
type Bundle struct {
	// Chain does not include the root anchor
	Chain       []*x509.Certificate
	Cert        *x509.Certificate
	IssuerCert  *x509.Certificate
	RootCert    *x509.Certificate
	Issuer      *pkix.Name
	Subject     *pkix.Name
	IssuerID    string
	SubjectID   string
	Expires     time.Time
	Hostnames   []string
	CertPEM     string
	CACertsPEM  string
	RootCertPEM string
}

// ExpiresInHours returns cert expiration rounded up in hours
func (b *Bundle) ExpiresInHours() time.Duration {
	return b.Expires.Sub(time.Now().UTC()) / time.Hour * time.Hour
}

// VerifyBundleFromPEM constructs and verifies the cert chain
func VerifyBundleFromPEM(certPEM, intCAPEM, rootPEM []byte, opt ...Option) (bundle *Bundle, status *BundleStatus, err error) {
	b, err := NewBundlerFromPEM(rootPEM, intCAPEM, opt...)
	if err != nil {
		err = errors.WithMessage(err, "failed to create bundler")
		return
	}

	c, err := b.ChainFromPEM(certPEM, nil, "")
	if err != nil {
		err = errors.WithMessage(err, "failed to bundle")
		return
	}
	return BuildBundle(c)
}

// BuildBundle returns Bundle
func BuildBundle(c *Chain) (bundle *Bundle, status *BundleStatus, err error) {
	var pemCert, pemRoot, pemCA string

	pemCert, err = EncodeToPEMString(false, c.Cert)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to encode cert to PEM")
	}

	pemRoot, err = EncodeToPEMString(false, c.Root)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to encode root cert to PEM")
	}

	if len(c.Chain) > 1 {
		pemCA, err = EncodeToPEMString(false, c.Chain[1:]...)
		if err != nil {
			return nil, nil, errors.WithMessage(err, "failed to encode CA chain to PEM")
		}
	}

	bundle = &Bundle{
		Chain:       c.Chain,
		Cert:        c.Cert,
		RootCert:    c.Root,
		IssuerCert:  FindIssuer(c.Cert, c.Chain, c.Root),
		Issuer:      c.Issuer,
		IssuerID:    GetIssuerID(c.Cert),
		Subject:     c.Subject,
		SubjectID:   GetSubjectID(c.Cert),
		Expires:     c.Expires,
		Hostnames:   c.Hostnames,
		CertPEM:     pemCert,
		CACertsPEM:  pemCA,
		RootCertPEM: pemRoot,
	}

	if len(c.Status.Messages) > 0 {
		logger.KV(xlog.WARNING, "CN", c.Cert.Subject.CommonName, "messages", strings.Join(c.Status.Messages, ";"))
	}
	if len(c.Status.ExpiringSKIs) > 0 {
		logger.KV(xlog.WARNING, "CN", c.Cert.Subject.CommonName, "ExpiringSKIs", strings.Join(c.Status.ExpiringSKIs, ";"))
	}
	if len(c.Status.Untrusted) > 0 {
		logger.KV(xlog.WARNING, "CN", c.Cert.Subject.CommonName, "Untrusted", strings.Join(c.Status.Untrusted, ";"))
	}

	status = &BundleStatus{
		ExpiringSKIs: c.Status.ExpiringSKIs,
		Untrusted:    c.Status.Untrusted,
		Messages:     c.Status.Messages,
	}

	return
}

// LoadAndVerifyBundleFromPEM constructs and verifies the cert chain
func LoadAndVerifyBundleFromPEM(certFile, intCAFile, rootFile string, opt ...Option) (*Bundle, *BundleStatus, error) {
	var err error
	var certPEM, intCAPEM, rootPEM []byte

	certPEM, err = os.ReadFile(certFile)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	if intCAFile != "" {
		intCAPEM, err = os.ReadFile(intCAFile)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
	}

	if rootFile != "" {
		rootPEM, err = os.ReadFile(rootFile)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
	}

	return VerifyBundleFromPEM(certPEM, intCAPEM, rootPEM, opt...)
}

// FindIssuer returns an issuer cert
func FindIssuer(crt *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) *x509.Certificate {
	if root != nil && bytes.Equal(crt.RawIssuer, root.RawSubject) {
		return root
	}
	for _, c := range chain {
		if c != nil && bytes.Equal(crt.RawIssuer, c.RawSubject) {
			return c
		}

	}
	return nil
}

// SortBundlesByExpiration returns bundles sorted by expiration in descending order
func SortBundlesByExpiration(bundles []*Bundle) []*Bundle {
	sorted := bundles[:]
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Expires.After(sorted[j].Expires)
	})
	return sorted
}
