package csr_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"strings"
	"testing"

	"uuid"

	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

// TestParseSAN_Classification checks the exact values and their order for
// each SAN type (XPKI-059).
func TestParseSAN_Classification(t *testing.T) {
	t.Parallel()
	san, err := csr.ParseSAN([]string{
		" www.Example.com ",
		"localhost",
		"*.example.com",
		"_acme-challenge.example.com",
		"10.0.0.1",
		"::1",
		"Admin <admin@example.com>",
		"ops@example.com",
		"spiffe://trusty/test",
		"https://example.com/path?q=1",
		"xn--bcher-kva.example",
		"a1-b2.c3",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"www.Example.com", "localhost", "*.example.com", "_acme-challenge.example.com", "xn--bcher-kva.example", "a1-b2.c3"}, san.DNSNames)
	assert.Equal(t, []string{"admin@example.com", "ops@example.com"}, san.EmailAddresses)
	assert.Equal(t, []net.IP{net.IPv4(10, 0, 0, 1).To4(), net.ParseIP("::1")}, san.IPAddresses)
	assert.Len(t, san.IPAddresses[0], net.IPv4len, "IPv4 addresses are kept in the 4-byte form")
	assert.Equal(t, []*url.URL{mustURL(t, "spiffe://trusty/test"), mustURL(t, "https://example.com/path?q=1")}, san.URIs)

	empty, err := csr.ParseSAN(nil)
	require.NoError(t, err)
	assert.Equal(t, &csr.SAN{}, empty)
	empty, err = csr.ParseSAN([]string{})
	require.NoError(t, err)
	assert.Equal(t, &csr.SAN{}, empty)
}

// TestParseSAN_Duplicates checks that duplicates of each type are dropped
// and the first occurrence wins (XPKI-059).
func TestParseSAN_Duplicates(t *testing.T) {
	t.Parallel()
	san, err := csr.ParseSAN([]string{
		"Example.com", "example.com", "EXAMPLE.COM", " example.com",
		"Ops@Example.com", "ops@example.com", "Ops <ops@example.com>",
		"10.0.0.1", "::ffff:10.0.0.1", "10.0.0.1", "::1", "0:0:0:0:0:0:0:1",
		"spiffe://trusty/test", "spiffe://trusty/test", " spiffe://trusty/test ",
		"bücher.example", "xn--bcher-kva.example", "Bücher.example",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Example.com", "xn--bcher-kva.example"}, san.DNSNames)
	assert.Equal(t, []string{"Ops@Example.com"}, san.EmailAddresses)
	assert.Equal(t, []net.IP{net.IPv4(10, 0, 0, 1).To4(), net.ParseIP("::1")}, san.IPAddresses)
	assert.Equal(t, []*url.URL{mustURL(t, "spiffe://trusty/test")}, san.URIs)
}

// TestParseSAN_DNS tables the DNS name rules (XPKI-059).
func TestParseSAN_DNS(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 63)
	for _, tc := range []struct {
		name string
		want string // the accepted A-label form, or "" when rejected
		err  string
	}{
		{name: "localhost", want: "localhost"},
		{name: "example", want: "example"},
		{name: "123", want: "123"},
		{name: "Mixed.Case.Example", want: "Mixed.Case.Example"},
		{name: "*.example.com", want: "*.example.com"},
		{name: "*.sub.example.com", want: "*.sub.example.com"},
		{name: "_sip._tcp.example.com", want: "_sip._tcp.example.com"},
		{name: "a-b.example", want: "a-b.example"},
		{name: long + ".example", want: long + ".example"},
		{name: strings.TrimSuffix(strings.Repeat(long+".", 4), ".")[:253], want: strings.TrimSuffix(strings.Repeat(long+".", 4), ".")[:253]},
		{name: "bücher.example", want: "xn--bcher-kva.example"},
		{name: "Bücher.Example", want: "xn--bcher-kva.example"},
		{name: "*.bücher.example", want: "*.xn--bcher-kva.example"},
		{name: "日本語.jp", want: "xn--wgv71a119e.jp"},
		{name: "", err: `invalid SAN "": empty name`},
		{name: "   ", err: `invalid SAN "   ": empty name`},
		{name: "foo bar", err: `invalid SAN "foo bar": invalid character ' ' in DNS label "foo bar"`},
		{name: "-foo.example", err: `invalid SAN "-foo.example": DNS label "-foo" starts or ends with a hyphen`},
		{name: "foo-.example", err: `invalid SAN "foo-.example": DNS label "foo-" starts or ends with a hyphen`},
		{name: "www.*.example.com", err: `invalid SAN "www.*.example.com": wildcard is not the first label`},
		{name: "*", err: `invalid SAN "*": wildcard without a domain`},
		{name: "*foo.example.com", err: `invalid SAN "*foo.example.com": invalid character '*' in DNS label "*foo"`},
		{name: "example.com.", err: `invalid SAN "example.com.": DNS name has a trailing dot`},
		{name: "a..b", err: `invalid SAN "a..b": empty DNS label`},
		{name: ".example.com", err: `invalid SAN ".example.com": empty DNS label`},
		{name: long + "a.example", err: `invalid SAN "` + long + `a.example": DNS label "` + long + `a" is longer than 63 characters`},
		{name: strings.Repeat(long+".", 4) + "b", err: "is longer than 253 characters"},
		{name: "exa/mple.com", err: `invalid SAN "exa/mple.com": invalid character '/' in DNS label "exa/mple"`},
		{name: "urn:example:animal", err: `invalid SAN "urn:example:animal": invalid character ':' in DNS label "urn:example:animal"`},
		{name: "\uFFFD.example", err: "invalid SAN \"\uFFFD.example\": invalid internationalized DNS name: idna: invalid label \"\uFFFD\""},
		{name: "-bü.example", err: `invalid SAN "-bü.example": invalid internationalized DNS name: idna: invalid label "-bü"`},
		{name: "bü cher.example", err: `invalid SAN "bü cher.example": invalid character ' ' in DNS label "xn--b cher-3ya"`},
		{name: "bü.xn--", err: `invalid SAN "bü.xn--": DNS name has a trailing dot`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			san, err := csr.ParseSAN([]string{tc.name})
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, san)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{tc.want}, san.DNSNames)
			assert.Empty(t, san.EmailAddresses)
			assert.Empty(t, san.IPAddresses)
			assert.Empty(t, san.URIs)
		})
	}
}

// TestParseSAN_URIAndEmail checks the URI and email rules and that every
// invalid name is reported in one error (XPKI-059).
func TestParseSAN_URIAndEmail(t *testing.T) {
	t.Parallel()
	san, err := csr.ParseSAN([]string{"http://[::1]:8080/x", "mailto://ops@example.com", "ops@example.com", "https://bücher.example/pä"})
	require.NoError(t, err)
	assert.Equal(t, []*url.URL{mustURL(t, "http://[::1]:8080/x"), mustURL(t, "mailto://ops@example.com"), mustURL(t, "https://bücher.example/pä")}, san.URIs)
	assert.Equal(t, "https://b%C3%BCcher.example/p%C3%A4", san.URIs[2].String(), "a non-ASCII host or path is percent-encoded, as x509 marshals it")
	assert.Equal(t, []string{"ops@example.com"}, san.EmailAddresses)

	_, err = csr.ParseSAN([]string{
		"http://a b/",
		"://nohost",
		"foo/://x",
		"https://example.com/?q=bü",
		"ops@bücher.example",
		"valid.example.com",
		"-invalid.example.com",
	})
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, `invalid SAN "http://a b/": invalid URI: parse "http://a b/": invalid character " " in host name`)
	assert.Contains(t, msg, `invalid SAN "://nohost": invalid URI: parse "://nohost": missing protocol scheme`)
	assert.Contains(t, msg, `invalid SAN "foo/://x": URI has no scheme`)
	assert.Contains(t, msg, `invalid SAN "https://example.com/?q=bü": URI is not ASCII`)
	assert.Contains(t, msg, `invalid SAN "ops@bücher.example": email address is not ASCII`)
	assert.Contains(t, msg, `invalid SAN "-invalid.example.com": DNS label "-invalid" starts or ends with a hyphen`)
	assert.NotContains(t, msg, `"valid.example.com"`)
	assert.Equal(t, 6, strings.Count(msg, "invalid SAN "), msg)
}

func sanTemplate() x509.Certificate {
	return x509.Certificate{
		DNSNames:       []string{"old.example.com"},
		EmailAddresses: []string{"old@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 168, 0, 1).To4()},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "old"}},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1}},
			{Id: oid.ExtensionSubjectAltName, Value: []byte{2}},
			{Id: asn1.ObjectIdentifier{1, 2, 3, 5}, Value: []byte{3}},
			{Id: oid.ExtensionSubjectAltName, Value: []byte{4}},
		},
	}
}

// TestApplySAN checks nil versus empty versus replacement, including the
// raw SAN extension, and that a failed call leaves the template unchanged
// (XPKI-059).
// TestSANValidate checks that already classified names, such as the names
// of a parsed CSR, get the ParseSAN rules and deduplication (XPKI-059).
func TestSANValidate(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		san := &csr.SAN{
			DNSNames:       []string{"Example.com", "example.com", "bücher.example"},
			EmailAddresses: []string{"Ops@Example.com", "ops@example.com"},
			IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.IPv4(10, 0, 0, 1), net.ParseIP("::1")},
			URIs:           []*url.URL{mustURL(t, "spiffe://trusty/a"), mustURL(t, "spiffe://trusty/a")},
		}
		require.NoError(t, san.Validate())
		assert.Equal(t, []string{"Example.com", "xn--bcher-kva.example"}, san.DNSNames)
		assert.Equal(t, []string{"Ops@Example.com"}, san.EmailAddresses)
		assert.Equal(t, []net.IP{net.IPv4(10, 0, 0, 1).To4(), net.ParseIP("::1")}, san.IPAddresses)
		assert.Equal(t, []*url.URL{mustURL(t, "spiffe://trusty/a")}, san.URIs)
	})
	t.Run("invalid leaves the names unchanged", func(t *testing.T) {
		san := &csr.SAN{
			DNSNames:       []string{"ok.example", "trailing.dot.", "a b"},
			EmailAddresses: []string{"", "ok@example.com", "not-an-email", "Ops <ops@example.com>"},
			IPAddresses:    []net.IP{{1, 2, 3}},
			URIs:           []*url.URL{{Path: "/no/scheme"}, nil},
		}
		before := *san
		err := san.Validate()
		require.Error(t, err)
		for _, want := range []string{
			`invalid SAN "trailing.dot.": DNS name has a trailing dot`,
			`invalid SAN "a b": invalid character ' ' in DNS label "a b"`,
			`invalid SAN "": empty email address`,
			`invalid SAN "not-an-email": invalid email address`,
			`invalid SAN "Ops <ops@example.com>": invalid email address`,
			`invalid SAN "?010203": invalid IP address length 3`,
			`invalid SAN "/no/scheme": URI has no scheme`,
			`invalid SAN "": nil URI`,
		} {
			assert.Contains(t, err.Error(), want)
		}
		assert.Equal(t, before, *san)
	})
	t.Run("nil template", func(t *testing.T) {
		err := csr.ApplySAN(nil, []string{"example.com"})
		assert.EqualError(t, err, "nil certificate template")
		assert.NotPanics(t, func() { csr.SetSAN(nil, []string{"example.com"}) })
	})
	t.Run("nil and empty", func(t *testing.T) {
		var san *csr.SAN
		require.NoError(t, san.Validate())
		empty := &csr.SAN{}
		require.NoError(t, empty.Validate())
		assert.Equal(t, &csr.SAN{}, empty)
	})
}

func TestApplySAN(t *testing.T) {
	t.Parallel()
	t.Run("nil keeps", func(t *testing.T) {
		template := sanTemplate()
		require.NoError(t, csr.ApplySAN(&template, nil))
		assert.Equal(t, sanTemplate(), template)
	})
	t.Run("empty clears", func(t *testing.T) {
		template := sanTemplate()
		require.NoError(t, csr.ApplySAN(&template, []string{}))
		assert.Nil(t, template.DNSNames)
		assert.Nil(t, template.EmailAddresses)
		assert.Nil(t, template.IPAddresses)
		assert.Nil(t, template.URIs)
		assert.Equal(t, []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{1}},
			{Id: asn1.ObjectIdentifier{1, 2, 3, 5}, Value: []byte{3}},
		}, template.ExtraExtensions, "every raw SAN extension is removed, the others keep their order")
	})
	t.Run("replaces", func(t *testing.T) {
		template := sanTemplate()
		shared := template.ExtraExtensions
		require.NoError(t, csr.ApplySAN(&template, []string{"new.example.com", "10.0.0.1", "new@example.com", "spiffe://new/x", "NEW.example.com"}))
		assert.Equal(t, []string{"new.example.com"}, template.DNSNames)
		assert.Equal(t, []string{"new@example.com"}, template.EmailAddresses)
		assert.Equal(t, []net.IP{net.IPv4(10, 0, 0, 1).To4()}, template.IPAddresses)
		assert.Equal(t, []*url.URL{mustURL(t, "spiffe://new/x")}, template.URIs)
		assert.Len(t, template.ExtraExtensions, 2)
		assert.Equal(t, sanTemplate().ExtraExtensions, shared, "the caller's extension slice is not modified")
	})
	t.Run("no SAN extension", func(t *testing.T) {
		template := x509.Certificate{ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}}}}
		exts := template.ExtraExtensions
		require.NoError(t, csr.ApplySAN(&template, []string{"a.example.com"}))
		assert.Equal(t, []string{"a.example.com"}, template.DNSNames)
		assert.Same(t, &exts[0], &template.ExtraExtensions[0], "extensions are not copied when none is removed")
	})
	t.Run("error keeps", func(t *testing.T) {
		template := sanTemplate()
		err := csr.ApplySAN(&template, []string{"new.example.com", "bad name"})
		require.EqualError(t, err, `invalid SAN "bad name": invalid character ' ' in DNS label "bad name"`)
		assert.Equal(t, sanTemplate(), template)
	})
}

// TestSetSAN_Lenient checks that the deprecated SetSAN applies the valid
// names and skips the invalid ones (XPKI-059).
func TestSetSAN_Lenient(t *testing.T) {
	t.Parallel()
	template := sanTemplate()
	csr.SetSAN(&template, []string{"bad name", "ok.example.com", "http://a b/", "10.0.0.1", "ok.example.com"})
	assert.Equal(t, []string{"ok.example.com"}, template.DNSNames)
	assert.Equal(t, []net.IP{net.IPv4(10, 0, 0, 1).To4()}, template.IPAddresses)
	assert.Nil(t, template.EmailAddresses)
	assert.Nil(t, template.URIs)
	assert.Len(t, template.ExtraExtensions, 2)

	kept := sanTemplate()
	csr.SetSAN(&kept, nil)
	assert.Equal(t, sanTemplate(), kept)

	cleared := sanTemplate()
	csr.SetSAN(&cleared, []string{})
	assert.Empty(t, cleared.DNSNames)
	assert.Empty(t, cleared.IPAddresses)
	assert.Len(t, cleared.ExtraExtensions, 2)
}

// TestSignRequest_SAN checks that a generated CSR carries the names
// ApplySAN produces, and that an invalid name fails the request (XPKI-059).
func TestSignRequest_SAN(t *testing.T) {
	t.Parallel()
	prov := inmemcrypto.NewProvider()
	csrProv := csr.NewProvider(prov)
	names := []string{"www.example.com", "WWW.example.com", "10.0.0.1", "::ffff:10.0.0.1", "ops@example.com", "spiffe://trusty/test", "bücher.example", "*.example.com"}
	req := csr.CertificateRequest{
		CommonName: "example.com",
		SAN:        names,
		KeyRequest: csr.NewKeyRequest(prov, "TestSignRequest_SAN"+uuid.NewV7().String(), "ECDSA", 256, csr.SigningKey),
	}
	csrPEM, _, _, err := csrProv.GenerateKeyAndRequest(&req)
	require.NoError(t, err)

	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, parsed.CheckSignature())

	var want x509.Certificate
	require.NoError(t, csr.ApplySAN(&want, names))
	assert.Equal(t, want.DNSNames, parsed.DNSNames)
	assert.Equal(t, []string{"www.example.com", "xn--bcher-kva.example", "*.example.com"}, parsed.DNSNames)
	assert.Equal(t, want.EmailAddresses, parsed.EmailAddresses)
	assert.Equal(t, want.IPAddresses, parsed.IPAddresses)
	assert.Len(t, parsed.IPAddresses, 1)
	require.Len(t, parsed.URIs, 1)
	assert.Equal(t, want.URIs[0].String(), parsed.URIs[0].String())

	// the parsed CSR names applied to a certificate template agree too
	tmpl, err := csr.ParsePEM(csrPEM)
	require.NoError(t, err)
	assert.Equal(t, want.DNSNames, tmpl.DNSNames)
	assert.Equal(t, want.IPAddresses, tmpl.IPAddresses)

	priv, err := prov.GetKey(req.KeyRequest.Label())
	if err != nil {
		// inmem keys are looked up by ID; regenerate is not needed: sign with a fresh key
		_, priv, _, err = csrProv.GenerateKeyAndRequest(&csr.CertificateRequest{
			CommonName: "example.com",
			KeyRequest: csr.NewKeyRequest(prov, "TestSignRequest_SAN2"+uuid.NewV7().String(), "ECDSA", 256, csr.SigningKey),
		})
		require.NoError(t, err)
	}
	req.SAN = []string{"ok.example.com", "bad name", "-bad.example.com"}
	_, err = csrProv.SignRequest(priv, &req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid SAN "bad name": invalid character ' ' in DNS label "bad name"`)
	assert.Contains(t, err.Error(), `invalid SAN "-bad.example.com": DNS label "-bad" starts or ends with a hyphen`)
	assert.NotContains(t, err.Error(), "ok.example.com")
}
