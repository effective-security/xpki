package certutil_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPEMMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.pem")
	require.NoError(t, os.WriteFile(invalid, []byte("invalid"), 0600))
	for _, file := range []string{invalid, filepath.Join(dir, "missing")} {
		_, err := certutil.LoadFromPEM(file)
		require.Error(t, err)
		_, err = certutil.LoadChainFromPEM(file)
		require.Error(t, err)
	}
	malformed := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not DER"),
	})
	_, err := certutil.ParseFromPEM(malformed)
	require.ErrorContains(t, err, "unable to parse certificate")
	_, err = certutil.CreatePoolFromPEM([]byte("invalid"))
	require.Error(t, err)
	_, err = certutil.EncodePublicKeyToPEM(struct{}{})
	require.Error(t, err)
	_, err = certutil.EncodePrivateKeyToPEM(struct{}{})
	require.ErrorContains(t, err, "unsupported key")
	_, err = certutil.ParsePrivateKeyPEM([]byte("invalid"))
	require.EqualError(t, err, "unable to decode private key")
	_, err = certutil.ParsePrivateKeyDER([]byte("invalid"))
	require.EqualError(t, err, "unable to parse private key")
	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte(" \n"), 0600))
	combined, err := certutil.LoadPEMFiles("", empty, invalid)
	require.NoError(t, err)
	assert.Equal(t, []byte("invalid"), combined)
	prefix, err := certutil.LoadPEMFiles(invalid, filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Equal(t, combined, prefix)
	for _, tc := range []struct {
		name, proc string
		password   []byte
		want       string
	}{
		{"password required", "4,ENCRYPTED", nil, "encrypted private key"},
		{"invalid encryption", "4,ENCRYPTED", []byte("password"), "no DEK-Info header in block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: map[string]string{"Proc-Type": tc.proc},
				Bytes:   []byte("key"),
			})
			_, err := certutil.GetKeyDERFromPEM(data, tc.password)
			require.ErrorContains(t, err, tc.want)
		})
	}
	plain := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,PLAIN"},
		Bytes:   []byte("key"),
	})
	params := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PARAMETERS",
		Bytes: []byte("parameters"),
	})
	data, err := certutil.GetKeyDERFromPEM(append(params, plain...), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("key"), data)
	_, edkey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(edkey)
	require.NoError(t, err)
	parsed, err := certutil.ParsePrivateKeyDER(der)
	require.NoError(t, err)
	assert.Equal(t, edkey, parsed)
	ecdhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err = x509.MarshalPKCS8PrivateKey(ecdhKey)
	require.NoError(t, err)
	_, err = certutil.ParsePrivateKeyDER(der)
	require.EqualError(t, err, "unable to parse private key")
}
