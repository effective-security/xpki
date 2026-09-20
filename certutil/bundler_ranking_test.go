package certutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOptimalChains(t *testing.T) {
	now := time.Now()
	early := &x509.Certificate{NotAfter: now.Add(time.Hour)}
	late := &x509.Certificate{NotAfter: now.Add(24 * time.Hour)}
	for _, tc := range []struct {
		name         string
		chains, want [][]*x509.Certificate
	}{
		{"empty", nil, nil},
		{"single", [][]*x509.Certificate{{early}}, [][]*x509.Certificate{{early}}},
		{"shorter wins", [][]*x509.Certificate{{late, late}, {early}}, [][]*x509.Certificate{{early}}},
		{"newer wins tie", [][]*x509.Certificate{{early}, {late}}, [][]*x509.Certificate{{late}}},
		{"retain newest", [][]*x509.Certificate{{late}, {early}}, [][]*x509.Certificate{{late}}},
		{"equal candidates", [][]*x509.Certificate{{late}, {late}}, [][]*x509.Certificate{{late}, {late}}},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, optimalChains(tc.chains)) })
	}
	assert.Empty(t, reverse(nil))
	assert.False(t, partialVerify(nil))
	assert.Empty(t, expirationWarning(nil))
	c := &Chain{}
	c.buildHostnames()
	assert.Nil(t, c.Hostnames)
	assert.Equal(t, 3*time.Second, httpClient(0).Timeout)
}
