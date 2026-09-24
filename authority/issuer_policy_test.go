package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	customOID      = asn1.ObjectIdentifier{1, 2, 3, 4}
	hostileDNSName = "evil.example.com"
	hostileKU      = []byte{0x03, 0x02, 0x02, 0x04}                                                 // keyCertSign
	hostileEKU     = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03} // codeSigning
	hostileAKI     = []byte{0x30, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04}
	hostileSKI     = []byte{0x04, 0x04, 0x01, 0x02, 0x03, 0x04}
	ocspNoCheckVal = []byte{0x05, 0x00}
)

// policyCSR returns a PEM CSR signed by key with the given raw extensions.
func policyCSR(t *testing.T, key crypto.Signer, dns []string, exts ...pkix.Extension) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "policy test"},
		DNSNames:        dns,
		ExtraExtensions: exts,
	}, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}))
}

// rawSAN encodes a subjectAltName extension with DNS names.
func rawSAN(t *testing.T, names ...string) pkix.Extension {
	t.Helper()
	var raw []asn1.RawValue
	for _, n := range names {
		raw = append(raw, asn1.RawValue{Tag: 2, Class: asn1.ClassContextSpecific, Bytes: []byte(n)})
	}
	value, err := asn1.Marshal(raw)
	require.NoError(t, err)
	return pkix.Extension{
		Id:    oid.ExtensionSubjectAltName,
		Value: value,
	}
}

// crlDP encodes a CRL distribution point extension with one URI.
func crlDP(t *testing.T, uri string) pkix.Extension {
	t.Helper()
	type distributionPointName struct {
		FullName []asn1.RawValue `asn1:"optional,tag:0"`
	}
	type distributionPoint struct {
		DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	}
	value, err := asn1.Marshal([]distributionPoint{{
		DistributionPoint: distributionPointName{
			FullName: []asn1.RawValue{{Tag: 6, Class: asn1.ClassContextSpecific, Bytes: []byte(uri)}},
		},
	}})
	require.NoError(t, err)
	return pkix.Extension{
		Id:    oid.ExtensionCRLDistributionPoints,
		Value: value,
	}
}

// assertUniqueExtensions fails if the certificate has repeated extension OIDs.
func assertUniqueExtensions(t *testing.T, crt *x509.Certificate) {
	t.Helper()
	seen := map[string]bool{}
	for _, ext := range crt.Extensions {
		id := ext.Id.String()
		assert.False(t, seen[id], "duplicate extension %s", id)
		seen[id] = true
	}
}

func extensionCount(crt *x509.Certificate, id asn1.ObjectIdentifier) int {
	count := 0
	for _, ext := range crt.Extensions {
		if ext.Id.Equal(id) {
			count++
		}
	}
	return count
}

func serverProfile() *CertProfile {
	return &CertProfile{
		Expiry: csr.Duration(time.Hour),
		Usage:  []string{"digital signature", "server auth"},
	}
}

// TestSignCSRProfileOwnedExtensions verifies XPKI-049: a hostile CSR cannot
// override the key usages, SAN, key identifiers or OCSP no-check that the
// issuer derives from the profile, even when the OID is allow-listed.
func TestSignCSRProfileOwnedExtensions(t *testing.T) {
	t.Parallel()
	hostile := func(t *testing.T) []pkix.Extension {
		return []pkix.Extension{
			{Id: oid.ExtensionKeyUsage, Critical: true, Value: hostileKU},
			{Id: oid.ExtensionExtendedKeyUsage, Value: hostileEKU},
			{Id: oid.ExtensionAuthorityKeyID, Value: hostileAKI},
			{Id: oid.ExtensionSubjectKeyID, Value: hostileSKI},
			{Id: oid.OCSPNoCheck, Value: ocspNoCheckVal},
			rawSAN(t, hostileDNSName),
		}
	}
	allOwned := []csr.OID{
		csr.OID(oid.ExtensionKeyUsage),
		csr.OID(oid.ExtensionExtendedKeyUsage),
		csr.OID(oid.ExtensionAuthorityKeyID),
		csr.OID(oid.ExtensionSubjectKeyID),
		csr.OID(oid.OCSPNoCheck),
		csr.OID(oid.ExtensionSubjectAltName),
	}
	for _, tc := range []struct {
		name    string
		fields  *csr.AllowedFields
		allowed []csr.OID
		omit    bool
	}{
		{name: "nil fields, empty allow-list"},
		{name: "nil fields, empty allow-list, omit", omit: true},
		{name: "nil fields, owned OIDs allow-listed", allowed: allOwned},
		{name: "subject only, SAN allow-listed", fields: &csr.AllowedFields{Subject: true}, allowed: allOwned},
		{name: "DNS allowed", fields: &csr.AllowedFields{Subject: true, DNSNames: true}, allowed: allOwned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, entity := ocspTestIssuer(t)
			issuer.cfg.OmitDisabledExtensions = tc.omit
			profile := serverProfile()
			profile.AllowedCSRFields = tc.fields
			profile.AllowedExtensions = tc.allowed
			require.NoError(t, profile.Validate())
			issuer.AddProfile("default", profile)

			dns := []string{"good.example.com"}
			// the raw SAN below replaces the DNSNames field in the CSR
			exts := hostile(t)
			if tc.fields == nil || tc.fields.DNSNames {
				exts[len(exts)-1] = rawSAN(t, dns...)
			}
			crt, _, err := issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, nil, exts...)})
			require.NoError(t, err)
			require.NoError(t, crt.CheckSignatureFrom(entity.Certificate))
			assertUniqueExtensions(t, crt)

			assert.Equal(t, x509.KeyUsageDigitalSignature, crt.KeyUsage)
			assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, crt.ExtKeyUsage)
			assert.Equal(t, entity.Certificate.SubjectKeyId, crt.AuthorityKeyId)
			assert.NotEqual(t, hostileSKI[2:], crt.SubjectKeyId)
			assert.False(t, certutil.HasOCSPNoCheck(crt))
			assert.NotContains(t, crt.DNSNames, hostileDNSName)
			if tc.fields == nil || tc.fields.DNSNames {
				assert.Equal(t, dns, crt.DNSNames)
			} else {
				assert.Empty(t, crt.DNSNames)
				assert.Nil(t, certutil.FindExtension(crt.Extensions, oid.ExtensionSubjectAltName))
			}
			assert.False(t, crt.IsCA)
		})
	}
}

// TestSignCSRSANBypassesFieldPolicy is the XPKI-049 reproduction: with
// DNS names disallowed and SAN allow-listed, a CSR SAN extension carried
// names past allowed_fields and the DNS regex.
func TestSignCSRSANBypassesFieldPolicy(t *testing.T) {
	t.Parallel()
	issuer, entity := ocspTestIssuer(t)
	profile := serverProfile()
	profile.AllowedDNS = `^good\.example\.com$`
	profile.AllowedCSRFields = &csr.AllowedFields{Subject: true}
	profile.AllowedExtensions = []csr.OID{csr.OID(oid.ExtensionSubjectAltName)}
	require.NoError(t, profile.Validate())
	issuer.AddProfile("default", profile)

	crt, _, err := issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, []string{hostileDNSName})})
	require.NoError(t, err)
	assert.Empty(t, crt.DNSNames)
	assert.Nil(t, certutil.FindExtension(crt.Extensions, oid.ExtensionSubjectAltName))

	// with DNS names allowed from the CSR the regex still applies
	profile.AllowedCSRFields.DNSNames = true
	_, _, err = issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, []string{hostileDNSName})})
	require.EqualError(t, err, "DNS Name does not match allowed list: "+hostileDNSName)
}

// TestSignCSRExtensionAllowList verifies XPKI-049: other CSR extensions are
// copied only when allow-listed; an empty allow-list denies them.
func TestSignCSRExtensionAllowList(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		allowed []csr.OID
		omit    bool
		want    string
		present bool
	}{
		{name: "empty list rejects", want: "extension not allowed: 1.2.3.4"},
		{name: "empty list omits", omit: true},
		{name: "other OID listed rejects", allowed: []csr.OID{{1, 2, 3, 5}}, want: "extension not allowed: 1.2.3.4"},
		{name: "other OID listed omits", allowed: []csr.OID{{1, 2, 3, 5}}, omit: true},
		{name: "listed", allowed: []csr.OID{csr.OID(customOID)}, present: true},
		{name: "listed with omit", allowed: []csr.OID{csr.OID(customOID)}, omit: true, present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, entity := ocspTestIssuer(t)
			issuer.cfg.OmitDisabledExtensions = tc.omit
			profile := serverProfile()
			profile.AllowedExtensions = tc.allowed
			issuer.AddProfile("default", profile)

			crt, data, err := issuer.Sign(csr.SignRequest{
				Request: policyCSR(t, entity.PrivateKey, nil, pkix.Extension{Id: customOID, Value: []byte{5, 0}}),
			})
			if tc.want != "" {
				require.EqualError(t, err, tc.want)
				assert.Nil(t, crt)
				assert.Nil(t, data)
				return
			}
			require.NoError(t, err)
			assertUniqueExtensions(t, crt)
			ext := certutil.FindExtension(crt.Extensions, customOID)
			if tc.present {
				require.NotNil(t, ext)
				assert.Equal(t, []byte{5, 0}, ext.Value)
			} else {
				assert.Nil(t, ext)
			}
		})
	}
}

// TestSignCSRIssuerGeneratedExtensions verifies that an allow-listed CSR CRL DP
// is kept only when the issuer does not generate one (SHAKEN delegate flow).
func TestSignCSRIssuerGeneratedExtensions(t *testing.T) {
	t.Parallel()
	const (
		csrCRL    = "http://csr.example.com/crl"
		issuerCRL = "http://issuer.example.com/crl"
	)
	for _, tc := range []struct {
		name      string
		issuerCRL string
		allowed   bool
		want      []string
	}{
		{name: "allow-listed, issuer has no CRL", allowed: true, want: []string{csrCRL}},
		{name: "allow-listed, issuer CRL wins", issuerCRL: issuerCRL, allowed: true, want: []string{issuerCRL}},
		{name: "not listed, issuer CRL", issuerCRL: issuerCRL, want: []string{issuerCRL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, entity := ocspTestIssuer(t)
			issuer.crlURL = tc.issuerCRL
			issuer.cfg.OmitDisabledExtensions = true
			profile := serverProfile()
			if tc.allowed {
				profile.AllowedExtensions = []csr.OID{csr.OID(oid.ExtensionCRLDistributionPoints)}
			}
			issuer.AddProfile("default", profile)

			crt, _, err := issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, nil, crlDP(t, csrCRL))})
			require.NoError(t, err)
			assertUniqueExtensions(t, crt)
			assert.Equal(t, tc.want, crt.CRLDistributionPoints)
		})
	}
}

// TestSignCSRIssuerGeneratedAIA verifies that the issuer AIA wins over an
// allow-listed CSR AIA, and that the CSR AIA is kept otherwise.
func TestSignCSRIssuerGeneratedAIA(t *testing.T) {
	t.Parallel()
	const (
		csrOCSP    = "http://csr.example.com/ocsp"
		issuerOCSP = "http://issuer.example.com/ocsp"
	)
	type accessDescription struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}
	value, err := asn1.Marshal([]accessDescription{{
		Method:   oid.AuthorityInfoAccessOcsp,
		Location: asn1.RawValue{Tag: 6, Class: asn1.ClassContextSpecific, Bytes: []byte(csrOCSP)},
	}})
	require.NoError(t, err)
	aia := pkix.Extension{
		Id:    oid.ExtensionAuthorityInfoAccess,
		Value: value,
	}
	for _, tc := range []struct {
		name, issuerOCSP string
		want             []string
	}{
		{name: "issuer has no AIA", want: []string{csrOCSP}},
		{name: "issuer AIA wins", issuerOCSP: issuerOCSP, want: []string{issuerOCSP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, entity := ocspTestIssuer(t)
			issuer.ocspURL = tc.issuerOCSP
			profile := serverProfile()
			profile.AllowedExtensions = []csr.OID{csr.OID(oid.ExtensionAuthorityInfoAccess)}
			issuer.AddProfile("default", profile)

			crt, _, err := issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, nil, aia)})
			require.NoError(t, err)
			assertUniqueExtensions(t, crt)
			assert.Equal(t, tc.want, crt.OCSPServer)
		})
	}
}

// TestSignExtensionPrecedence verifies XPKI-050: exactly one extension per
// OID, with profile > SignRequest > CSR precedence.
func TestSignExtensionPrecedence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		profile, ra bool
		csrValue    []byte
		want        []byte
	}{
		{name: "CSR only", csrValue: []byte{0x01, 0x01, 0x00}, want: []byte{0x01, 0x01, 0x00}},
		{name: "RA over CSR", ra: true, csrValue: []byte{0x01, 0x01, 0x00}, want: []byte{0x02, 0x01, 0x07}},
		{name: "profile over CSR", profile: true, csrValue: []byte{0x01, 0x01, 0x00}, want: []byte{0x05, 0x00}},
		{name: "profile over RA and CSR", profile: true, ra: true, csrValue: []byte{0x01, 0x01, 0x00}, want: []byte{0x05, 0x00}},
		{name: "identical profile and CSR", profile: true, csrValue: []byte{0x05, 0x00}, want: []byte{0x05, 0x00}},
		{name: "profile over RA", profile: true, ra: true, want: []byte{0x05, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, entity := ocspTestIssuer(t)
			profile := serverProfile()
			profile.AllowedExtensions = []csr.OID{csr.OID(customOID)}
			if tc.profile {
				profile.Extensions = []csr.X509Extension{{ID: csr.OID(customOID), Critical: true, Value: "hex:0500"}}
			}
			require.NoError(t, profile.Validate())
			issuer.AddProfile("default", profile)

			req := csr.SignRequest{}
			if tc.ra {
				req.Extensions = []csr.X509Extension{{ID: csr.OID(customOID), Value: "hex:020107"}}
			}
			var exts []pkix.Extension
			if tc.csrValue != nil {
				exts = append(exts, pkix.Extension{Id: customOID, Value: tc.csrValue})
			}
			req.Request = policyCSR(t, entity.PrivateKey, nil, exts...)

			crt, _, err := issuer.Sign(req)
			require.NoError(t, err)
			assertUniqueExtensions(t, crt)
			require.Equal(t, 1, extensionCount(crt, customOID))
			ext := certutil.FindExtension(crt.Extensions, customOID)
			assert.Equal(t, tc.want, ext.Value)
			assert.Equal(t, tc.profile, ext.Critical)
		})
	}
}

// TestSignProfileGeneratedExtensionsWin verifies XPKI-050 for extensions that
// fillTemplate generates from profile fields.
func TestSignProfileGeneratedExtensionsWin(t *testing.T) {
	t.Parallel()
	issuer, entity := ocspTestIssuer(t)
	profile := &CertProfile{
		Expiry:      csr.Duration(time.Hour),
		Usage:       []string{"digital signature", "ocsp signing"},
		OCSPNoCheck: true,
		Policies:    []csr.CertificatePolicy{{ID: csr.OID{1, 2, 1000, 1}}},
	}
	require.NoError(t, profile.Validate())
	issuer.AddProfile("default", profile)

	crt, _, err := issuer.Sign(csr.SignRequest{
		Request: policyCSR(t, entity.PrivateKey, nil),
		Extensions: []csr.X509Extension{
			{ID: csr.OID(oid.ExtensionCertificatePolicies), Value: "hex:3000"},
			{ID: csr.OID(oid.OCSPNoCheck), Critical: true, Value: "hex:0500"},
		},
	})
	require.NoError(t, err)
	assertUniqueExtensions(t, crt)
	assert.Equal(t, []asn1.ObjectIdentifier{{1, 2, 1000, 1}}, crt.PolicyIdentifiers)
	noCheck := certutil.FindExtension(crt.Extensions, oid.OCSPNoCheck)
	require.NotNil(t, noCheck)
	assert.False(t, noCheck.Critical)
}

// TestSignRAMayOverrideOwnedExtensions verifies that the trusted RA request
// may still supply an allow-listed profile-owned OID, such as a critical
// timestamping EKU.
func TestSignRAMayOverrideOwnedExtensions(t *testing.T) {
	t.Parallel()
	issuer, entity := ocspTestIssuer(t)
	profile := &CertProfile{
		Expiry:            csr.Duration(time.Hour),
		Usage:             []string{"digital signature", "timestamping"},
		AllowedExtensions: []csr.OID{csr.OID(oid.ExtensionExtendedKeyUsage)},
	}
	require.NoError(t, profile.Validate())
	issuer.AddProfile("default", profile)

	crt, _, err := issuer.Sign(csr.SignRequest{
		Request: policyCSR(t, entity.PrivateKey, nil),
		Extensions: []csr.X509Extension{{
			ID:       csr.OID(oid.ExtensionExtendedKeyUsage),
			Critical: true,
			Value:    "hex:300a06082b06010505070308",
		}},
	})
	require.NoError(t, err)
	assertUniqueExtensions(t, crt)
	eku := certutil.FindExtension(crt.Extensions, oid.ExtensionExtendedKeyUsage)
	require.NotNil(t, eku)
	assert.True(t, eku.Critical)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, crt.ExtKeyUsage)
}

func TestProfileValidateExtensions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		profile CertProfile
		want    string
	}{
		{
			name: "repeated OID",
			profile: CertProfile{
				Extensions: []csr.X509Extension{
					{ID: csr.OID(customOID), Value: "hex:0500"},
					{ID: csr.OID(customOID), Value: "hex:0400"},
				},
			},
			want: "duplicate extension: 1.2.3.4",
		},
		{
			name: "policies conflict",
			profile: CertProfile{
				Policies:   []csr.CertificatePolicy{{ID: csr.OID{1, 2, 3}}},
				Extensions: []csr.X509Extension{{ID: csr.OID(oid.ExtensionCertificatePolicies), Value: "hex:3000"}},
			},
			want: "extension 2.5.29.32 conflicts with profile policies",
		},
		{
			name: "OCSP no-check conflict",
			profile: CertProfile{
				OCSPNoCheck: true,
				Extensions:  []csr.X509Extension{{ID: csr.OID(oid.OCSPNoCheck), Value: "hex:0500"}},
			},
			want: "extension 1.3.6.1.5.5.7.48.1.5 conflicts with ocsp_no_check",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.profile.Expiry = csr.Duration(time.Hour)
			tc.profile.Usage = []string{"digital signature"}
			require.EqualError(t, tc.profile.Validate(), tc.want)
		})
	}

	// unvalidated profiles added directly are rejected at signing time
	issuer, entity := ocspTestIssuer(t)
	issuer.AddProfile("default", &CertProfile{
		Expiry: csr.Duration(time.Hour),
		Usage:  []string{"digital signature"},
		Extensions: []csr.X509Extension{
			{ID: csr.OID(customOID), Value: "hex:0500"},
			{ID: csr.OID(customOID), Value: "hex:0400"},
		},
	})
	crt, data, err := issuer.Sign(csr.SignRequest{Request: policyCSR(t, entity.PrivateKey, nil)})
	require.EqualError(t, err, "duplicate profile extension: 1.2.3.4")
	assert.Nil(t, crt)
	assert.Nil(t, data)
}

// TestValidityWindow verifies XPKI-054 against a fixed clock.
func TestValidityWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 24, 12, 0, 20, 0, time.UTC)
	const (
		expiry   = 10 * time.Hour
		backdate = 30 * time.Minute
	)
	profile := &CertProfile{
		Expiry:   csr.Duration(expiry),
		Backdate: csr.Duration(backdate),
	}
	defaultNB := now.Round(time.Minute).Add(-backdate)
	earliest := now.Truncate(time.Minute).Add(-backdate)
	for _, tc := range []struct {
		name           string
		profile        *CertProfile
		nb, na         time.Time
		wantNB, wantNA time.Time
		want           string
	}{
		{name: "defaults", wantNB: defaultNB, wantNA: defaultNB.Add(expiry)},
		{
			name:    "default backdate",
			profile: &CertProfile{Expiry: csr.Duration(expiry)},
			wantNB:  now.Round(time.Minute).Add(-defaultBackdate),
			wantNA:  now.Round(time.Minute).Add(-defaultBackdate).Add(expiry),
		},
		{name: "shorter lifetime", nb: now, na: now.Add(time.Hour), wantNB: now, wantNA: now.Add(time.Hour)},
		{name: "exact profile lifetime", nb: now, na: now.Add(expiry), wantNB: now, wantNA: now.Add(expiry)},
		{name: "overlong", nb: now, na: now.Add(expiry + time.Second), want: "validity 10h0m1s exceeds profile expiry 10h0m0s"},
		{name: "overlong NotAfter only", na: now.Add(expiry), want: "validity 10h30m20s exceeds profile expiry 10h0m0s"},
		{name: "NotAfter only", na: now.Add(time.Hour), wantNB: defaultNB, wantNA: now.Add(time.Hour)},
		{name: "earliest backdate", nb: earliest, wantNB: earliest, wantNA: earliest.Add(expiry)},
		{name: "excessive backdate", nb: earliest.Add(-time.Second), want: "NotBefore 2026-09-24T11:29:59Z is earlier than allowed 2026-09-24T11:30:00Z"},
		{name: "future NotBefore", nb: now.Add(24 * time.Hour), wantNB: now.Add(24 * time.Hour), wantNA: now.Add(24*time.Hour + expiry)},
		{name: "equal", nb: now, na: now, want: "invalid validity: NotAfter 2026-09-24T12:00:20Z is not after NotBefore 2026-09-24T12:00:20Z"},
		{name: "reversed", nb: now, na: now.Add(-time.Minute), want: "invalid validity: NotAfter 2026-09-24T11:59:20Z is not after NotBefore 2026-09-24T12:00:20Z"},
		{
			name:    "no expiry, explicit NotAfter",
			profile: &CertProfile{},
			na:      now.Add(1000 * time.Hour),
			wantNB:  now.Round(time.Minute).Add(-defaultBackdate),
			wantNA:  now.Add(1000 * time.Hour),
		},
		{name: "no expiry", profile: &CertProfile{}, want: "expiry is not set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := profile
			if tc.profile != nil {
				p = tc.profile
			}
			nb, na, err := validityWindow(p, now, tc.nb, tc.na)
			if tc.want != "" {
				require.EqualError(t, err, tc.want)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantNB, nb)
			assert.Equal(t, tc.wantNA, na)
			assert.Equal(t, time.UTC, nb.Location())
			assert.Equal(t, time.UTC, na.Location())
		})
	}
}

// TestSignValidity verifies XPKI-054 through Sign, including issuer-expiry clipping.
func TestSignValidity(t *testing.T) {
	t.Parallel()
	issuer, entity := ocspTestIssuer(t)
	caNotAfter := entity.Certificate.NotAfter
	profile := &CertProfile{
		Expiry: csr.Duration(100 * 365 * 24 * time.Hour),
		Usage:  []string{"digital signature"},
	}
	issuer.AddProfile("default", profile)
	request := policyCSR(t, entity.PrivateKey, nil)
	now := time.Now().UTC().Truncate(time.Second)

	crt, _, err := issuer.Sign(csr.SignRequest{Request: request, NotBefore: now, NotAfter: now.Add(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, now, crt.NotBefore.UTC())
	assert.Equal(t, now.Add(time.Hour), crt.NotAfter.UTC())

	crt, _, err = issuer.Sign(csr.SignRequest{Request: request, NotBefore: now, NotAfter: caNotAfter.Add(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, caNotAfter.UTC(), crt.NotAfter.UTC())

	crt, data, err := issuer.Sign(csr.SignRequest{Request: request, NotBefore: caNotAfter.Add(time.Hour)})
	require.ErrorContains(t, err, "is not before issuer NotAfter")
	assert.Nil(t, crt)
	assert.Nil(t, data)

	_, _, err = issuer.Sign(csr.SignRequest{Request: request, NotBefore: now, NotAfter: now})
	require.ErrorContains(t, err, "failed to populate template: invalid validity")

	profile.Expiry = csr.Duration(time.Hour)
	_, _, err = issuer.Sign(csr.SignRequest{Request: request, NotBefore: now, NotAfter: now.Add(2 * time.Hour)})
	require.EqualError(t, err, "failed to populate template: validity 2h0m0s exceeds profile expiry 1h0m0s")
}
