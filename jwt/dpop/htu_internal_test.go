package dpop

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeHTU(t *testing.T) {
	t.Parallel()
	tcases := []struct {
		in  string
		exp string
		err string
	}{
		{in: "https://h/x", exp: "https://h/x"},
		{in: "HTTPS://H.Example/X", exp: "https://h.example/X"},
		{in: "https://h", exp: "https://h/"},
		{in: "https://h:/x", exp: "https://h/x"},
		{in: "https://h:443/x", exp: "https://h/x"},
		{in: "http://h:80/x", exp: "http://h/x"},
		{in: "http://h:443/x", exp: "http://h:443/x"},
		{in: "https://h:8443/x", exp: "https://h:8443/x"},
		{in: "https://[::1]:443/x", exp: "https://[::1]/x"},
		{in: "https://h/x?q=1#frag", exp: "https://h/x"},
		{in: "https://h/%7e%41%2f%2F%c3%A9", exp: "https://h/~A%2F%2F%C3%A9"},
		// dot segments are compared as received
		{in: "https://h/a/./b/../c", exp: "https://h/a/./b/../c"},
		{in: "https://h/a/b/..", exp: "https://h/a/b/.."},
		{in: "https://h/../a", exp: "https://h/../a"},
		{in: "https://h/a/%2E%2E/b", exp: "https://h/a/../b"},
		{in: "https://h/a..b/.c", exp: "https://h/a..b/.c"},
		{in: "https://h//a//b/", exp: "https://h//a//b/"},
		{in: "/x", err: `invalid URI "/x"`},
		{in: "https:///x", err: `invalid URI "https:///x"`},
		{in: "https:h/x", err: `invalid URI "https:h/x"`},
		{in: "https://u:p@h/x", err: `invalid URI "https://u:p@h/x"`},
		{in: "https://h/%zz", err: `invalid URI "https://h/%zz": parse "https://h/%zz": invalid URL escape "%zz"`},
	}
	for _, tc := range tcases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeHTU(tc.in)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.exp, got)
		})
	}
}

func TestNormalizePercentEncoding(t *testing.T) {
	t.Parallel()
	// a truncated escape is copied as is; EscapedPath never produces one
	assert.Equal(t, "/a%4", normalizePercentEncoding("/a%4"))
	assert.Equal(t, "/a%", normalizePercentEncoding("/a%"))
	assert.Equal(t, "/plain", normalizePercentEncoding("/plain"))
}
