package cryptoprov_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePin writes a PIN file with surrounding whitespace and returns its path.
func writePin(t *testing.T, pin string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pin.txt")
	require.NoError(t, os.WriteFile(path, []byte(" "+pin+"\n"), 0600))
	return path
}

func Test_ParseTokenURI(t *testing.T) {
	pinFile := writePin(t, "filepin")
	libPath := filepath.Join(string(filepath.Separator), "usr", "lib", "softhsm", "libsofthsm2.so")

	type want struct {
		man, mod, serial, label, path, pin string
	}
	tcases := []struct {
		name string
		uri  string
		want want
		// err is a fragment of the error; errors wrap ErrInvalidURI
		err string
		// cause, when set, must be in the error chain too
		cause error
	}{
		{
			name: "path attributes",
			uri:  "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=inmemoryRSA",
			want: want{man: "testprov", mod: "inmem", serial: "20764350726", label: "inmemoryRSA"},
		},
		{
			name: "query pin-value",
			uri:  "pkcs11:token=xpki?pin-value=1234",
			want: want{label: "xpki", pin: "1234"},
		},
		{
			name: "query module-path",
			uri:  "pkcs11:token=xpki?module-path=" + libPath,
			want: want{label: "xpki", path: libPath},
		},
		{
			name: "query module-name",
			uri:  "pkcs11:token=xpki?module-name=softhsm2",
			want: want{label: "xpki", path: "softhsm2"},
		},
		{
			name: "module-path overrides module-name",
			uri:  "pkcs11:token=xpki?module-name=softhsm2&module-path=" + libPath + "&pin-value=1234",
			want: want{label: "xpki", path: libPath, pin: "1234"},
		},
		{
			name: "query pin-source",
			uri:  "pkcs11:token=xpki?pin-source=file://" + pinFile,
			want: want{label: "xpki", pin: "filepin"},
		},
		{
			name: "legacy path pin-value",
			uri:  "pkcs11:token=xpki;pin-value=1234",
			want: want{label: "xpki", pin: "1234"},
		},
		{
			name: "legacy path module-path and pin-source",
			uri:  "pkcs11:token=xpki;module-path=" + libPath + ";pin-source=file:" + pinFile,
			want: want{label: "xpki", path: libPath, pin: "filepin"},
		},
		{
			name: "encoded delimiters",
			uri:  "pkcs11:token=a%3Bb%26c%3Fd%3De;serial=1?pin-value=p%26q%3Dr",
			want: want{label: "a;b&c?d=e", serial: "1", pin: "p&q=r"},
		},
		{
			name: "literal plus and ampersand in path",
			uri:  "pkcs11:token=a+b&c;serial=1+2",
			want: want{label: "a+b&c", serial: "1+2"},
		},
		{
			name: "manufacturer and model trimmed",
			uri:  "pkcs11:manufacturer=SoftHSM%20project%20%20%00;model=%20SoftHSM%20v2%20;token=%20spaced%20",
			want: want{man: "SoftHSM project", mod: "SoftHSM v2", label: " spaced "},
		},
		{
			name: "unknown and vendor attributes ignored",
			uri:  "pkcs11:token=xpki;library-version=2.6;slot-id=1;x-vendor=a?x-q=1&x-q=2&pin-value=z",
			want: want{label: "xpki", pin: "z"},
		},
		{
			name: "surrounding whitespace",
			uri:  " \tpkcs11:token=xpki?pin-value=1\n",
			want: want{label: "xpki", pin: "1"},
		},
		{
			name: "scheme is case-insensitive",
			uri:  "PKCS11:token=xpki",
			want: want{label: "xpki"},
		},
		{
			name: "empty path and query",
			uri:  "pkcs11:?",
		},
		{
			name: "empty path with query",
			uri:  "pkcs11:?pin-value=1",
			want: want{pin: "1"},
		},
		{
			name: "empty value counts as absent",
			uri:  "pkcs11:token=;serial=1?module-path=",
			want: want{serial: "1"},
		},
		{
			// accepted before XPKI-027 (url.ParseQuery ignored empty segments)
			name: "trailing and doubled separators are ignored",
			uri:  "pkcs11:token=a;;serial=1;?pin-value=1&&",
			want: want{label: "a", serial: "1", pin: "1"},
		},
		{name: "empty", uri: "", err: "scheme is not pkcs11"},
		{name: "no colon", uri: "pkcs11", err: "scheme is not pkcs11"},
		{name: "other scheme", uri: "https://example.com/?pin-value=1", err: "scheme is not pkcs11"},
		{name: "segment without value", uri: "pkcs11:token", err: `path attribute "token": missing '='`},
		{name: "invalid attribute name", uri: "pkcs11:to ken=a", err: `path attribute "to ken=a": invalid attribute name`},
		{name: "invalid escaping in path", uri: "pkcs11:token=%zz", err: `path attribute "token=%zz": invalid percent-encoding`},
		{name: "invalid escaping in query", uri: "pkcs11:token=a?module-name=%4", err: `query attribute "module-name=%4": invalid percent-encoding`},
		{name: "duplicate path attribute", uri: "pkcs11:token=a;serial=1;token=b", err: `duplicate path attribute "token"`},
		{name: "duplicate query attribute", uri: "pkcs11:token=a?pin-value=1&pin-value=2", err: `duplicate query attribute "pin-value"`},
		{name: "attribute in path and query", uri: "pkcs11:token=a;pin-value=1?pin-value=2", err: `attribute "pin-value" in both path and query`},
		{name: "module-name in path and query", uri: "pkcs11:token=a;module-name=x?module-name=y", err: `attribute "module-name" in both path and query`},
		{name: "pin-source and pin-value", uri: "pkcs11:token=a?pin-source=file:" + pinFile + "&pin-value=1", err: "both pin-source and pin-value are present"},
		{name: "pin-source and legacy pin-value", uri: "pkcs11:token=a;pin-value=1?pin-source=file:" + pinFile, err: "both pin-source and pin-value are present"},
		{name: "pin-source and empty pin-value", uri: "pkcs11:token=a?pin-source=file:" + pinFile + "&pin-value=", err: "both pin-source and pin-value are present"},
		{name: "relative module-path", uri: "pkcs11:token=a?module-path=lib/softhsm.so", err: `module-path "lib/softhsm.so" is not absolute`},
		{name: "pin-source not a file URI", uri: "pkcs11:token=a?pin-source=https://example.com/pin", err: "pin-source: only file: URIs are supported"},
		{name: "pin-source without path", uri: "pkcs11:token=a?pin-source=file:", err: "pin-source: only file: URIs are supported"},
		{name: "pin-source missing file", uri: "pkcs11:token=a?pin-source=file:" + pinFile + ".missing", err: "pin-source: read " + pinFile + ".missing: ", cause: fs.ErrNotExist},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := cryptoprov.ParseTokenURI(tc.uri)
			if tc.err != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, cryptoprov.ErrInvalidURI)
				assert.Contains(t, err.Error(), tc.err)
				assert.Nil(t, c)
				if tc.cause != nil {
					assert.ErrorIs(t, err, tc.cause, "the cause must stay inspectable")
					var pathErr *fs.PathError
					assert.ErrorAs(t, err, &pathErr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want.man, c.Manufacturer())
			assert.Equal(t, tc.want.mod, c.Model())
			assert.Equal(t, tc.want.serial, c.TokenSerial())
			assert.Equal(t, tc.want.label, c.TokenLabel())
			assert.Equal(t, tc.want.path, c.Path())
			assert.Equal(t, tc.want.pin, c.Pin())
			assert.Empty(t, c.Attributes())
		})
	}
}

// Test_ParseTokenURI_RedactsPIN checks that no error quotes a pin-value,
// whatever its placement.
func Test_ParseTokenURI_RedactsPIN(t *testing.T) {
	for _, uri := range []string{
		"pkcs11:token=a;pin-value=s3cret-path?pin-value=s3cret-query",
		"pkcs11:token=a?pin-value=s3cret-query&pin-value=s3cret-dup",
		"pkcs11:token=a;pin-value=s3cret-path;token=b",
		"pkcs11:pin-value=s3cret-path;bad",
		"pkcs11:token=a?pin-value=s3cret-query&module-path=relative.so",
		"pkcs11:token=a?pin-value=s3cret-query&module-name=%zz",
		"pkcs11:token=a?pin-value=s3cret-query&pin-source=file:/nonexistent/pin",
		// a query value may contain ";" and a path value "&" (RFC 7512 §2.3)
		"pkcs11:token=x?pin-value=s3cret;s3cret-tail&module-path=relative.so",
		"pkcs11:pin-value=s3cret&s3cret-tail;token=x?module-path=relative.so",
		"pkcs11:token=x?pin-value=s3cret;s3cret-tail&module-name=%zz",
		"pkcs11:pin-value=s3cret&s3cret-tail;bad",
		"pkcs11:token=x?module-name=%zz&pin-value=s3cret;s3cret-tail",
	} {
		_, err := cryptoprov.ParseTokenURI(uri)
		require.Error(t, err, uri)
		assert.NotContains(t, err.Error(), "s3cret", "%s: %s", uri, err.Error())
		assert.Contains(t, err.Error(), "pin-value=***", "%s: %s", uri, err.Error())
	}
	// the other attributes stay readable
	_, err := cryptoprov.ParseTokenURI("pkcs11:token=x?pin-value=s3cret;tail&module-path=relative.so")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"pkcs11:token=x?pin-value=***&module-path=relative.so"`)
	_, err = cryptoprov.ParseTokenURI("pkcs11:pin-value=s3cret&tail;token=x?module-path=relative.so")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"pkcs11:pin-value=***;token=x?module-path=relative.so"`)
}

func Test_ParsePrivateKeyURI(t *testing.T) {
	type want struct {
		man, mod, serial, label, id string
	}
	tcases := []struct {
		name string
		uri  string
		want want
		err  error
		msg  string
	}{
		{
			name: "full",
			uri:  "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=inmemoryRSA;id=123;type=private",
			want: want{man: "testprov", mod: "inmem", serial: "20764350726", label: "inmemoryRSA", id: "123"},
		},
		{
			name: "minimal",
			uri:  "pkcs11:serial=1;id=k;type=private",
			want: want{serial: "1", id: "k"},
		},
		{
			name: "percent-encoded binary id",
			uri:  "pkcs11:serial=1;id=%01%02%ff%2F;type=private",
			want: want{serial: "1", id: "\x01\x02\xff/"},
		},
		{
			name: "id with slashes and colons",
			uri:  "pkcs11:manufacturer=GCPKMS;model=KMS;id=rot/cryptoKeyVersions/1;serial=1;type=private",
			want: want{man: "GCPKMS", mod: "KMS", serial: "1", id: "rot/cryptoKeyVersions/1"},
		},
		{
			name: "manufacturer trimmed without pin-source",
			uri:  "pkcs11:manufacturer=SoftHSM%20project%20%00;model=SoftHSM%20v2%20;serial=1;id=2;type=private",
			want: want{man: "SoftHSM project", mod: "SoftHSM v2", serial: "1", id: "2"},
		},
		{
			name: "query attributes accepted",
			uri:  "pkcs11:serial=1;id=k;type=private?pin-value=1234&module-path=/usr/lib/p11.so",
			want: want{serial: "1", id: "k"},
		},
		{
			name: "legacy pin-value in path",
			uri:  "pkcs11:serial=1;id=k;type=private;pin-value=1234",
			want: want{serial: "1", id: "k"},
		},
		{
			name: "whitespace and newline",
			uri:  "pkcs11:serial=1;id=k;type=private\n",
			want: want{serial: "1", id: "k"},
		},
		{name: "not pkcs11", uri: "https://example.com", err: cryptoprov.ErrInvalidURI, msg: "scheme is not pkcs11"},
		{name: "missing type", uri: "pkcs11:serial=1;id=k", err: cryptoprov.ErrInvalidPrivateKeyURI, msg: "type=private, serial and id are required"},
		{name: "public type", uri: "pkcs11:serial=1;id=k;type=public", err: cryptoprov.ErrInvalidPrivateKeyURI},
		{name: "missing serial", uri: "pkcs11:id=k;type=private", err: cryptoprov.ErrInvalidPrivateKeyURI},
		{name: "missing id", uri: "pkcs11:serial=1;type=private", err: cryptoprov.ErrInvalidPrivateKeyURI},
		{name: "empty id", uri: "pkcs11:serial=1;id=;type=private", err: cryptoprov.ErrInvalidPrivateKeyURI},
		{name: "duplicate id", uri: "pkcs11:serial=1;id=a;id=b;type=private", err: cryptoprov.ErrInvalidURI, msg: `duplicate path attribute "id"`},
		{name: "duplicate query", uri: "pkcs11:serial=1;id=k;type=private?pin-value=1&pin-value=2", err: cryptoprov.ErrInvalidURI, msg: `duplicate query attribute "pin-value"`},
		{name: "pin conflict", uri: "pkcs11:serial=1;id=k;type=private?pin-value=1&pin-source=file:/p", err: cryptoprov.ErrInvalidURI, msg: "both pin-source and pin-value"},
		{name: "bad escape in id", uri: "pkcs11:serial=1;id=%zz;type=private", err: cryptoprov.ErrInvalidURI, msg: "invalid percent-encoding"},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := cryptoprov.ParsePrivateKeyURI(tc.uri)
			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
				if tc.msg != "" {
					assert.Contains(t, err.Error(), tc.msg)
				}
				assert.NotContains(t, err.Error(), "pin-value=1")
				assert.Nil(t, uri)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want.man, uri.Manufacturer())
			assert.Equal(t, tc.want.mod, uri.Model())
			assert.Equal(t, tc.want.serial, uri.TokenSerial())
			assert.Equal(t, tc.want.label, uri.TokenLabel())
			assert.Equal(t, tc.want.id, uri.ID())
		})
	}
}
