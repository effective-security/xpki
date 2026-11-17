package pagetoken_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/effective-security/xpki/v2/internal/pagetoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cursor struct {
	Marker string `json:"m,omitempty"`
	Offset int    `json:"o,omitempty"`
}

func binding(t *testing.T, v any) []byte {
	t.Helper()
	b, err := pagetoken.Binding(v)
	require.NoError(t, err)
	return b
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	bound := binding(t, map[string]string{"label": "ca"})
	token, err := pagetoken.Encode(bound, cursor{Marker: "next", Offset: 7})
	require.NoError(t, err)
	assert.NotContains(t, token, "=", "unpadded base64url")

	var got cursor
	require.NoError(t, pagetoken.Decode(bound, token, &got))
	assert.Equal(t, cursor{Marker: "next", Offset: 7}, got)
}

func TestBinding(t *testing.T) {
	t.Parallel()
	a := binding(t, map[string]string{"b": "2", "a": "1"})
	// map keys are encoded in order, so the binding does not depend on it
	assert.Equal(t, a, binding(t, map[string]string{"a": "1", "b": "2"}))
	assert.NotEqual(t, a, binding(t, map[string]string{"a": "1"}))
	assert.Len(t, a, 8)

	_, err := pagetoken.Binding(make(chan int))
	require.ErrorContains(t, err, "unable to encode page token binding")
}

func TestDecodeRejects(t *testing.T) {
	t.Parallel()
	bound := binding(t, "request")
	token, err := pagetoken.Encode(bound, cursor{Offset: 1})
	require.NoError(t, err)

	otherVersion := base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"b":"AAAA","p":{}}`))
	notAnObject, err := pagetoken.Encode(bound, "text")
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		binding []byte
		token   string
		msg     string
	}{
		"another binding": {
			binding: binding(t, "another request"),
			token:   token,
			msg:     "issued for another request",
		},
		"not base64": {
			binding: bound,
			token:   "not a token",
			msg:     "not base64url",
		},
		"not json": {
			binding: bound,
			token:   base64.RawURLEncoding.EncodeToString([]byte("text")),
			msg:     "not a token",
		},
		"another version": {
			binding: bound,
			token:   otherVersion,
			msg:     "unsupported version 2",
		},
		"another payload": {
			binding: bound,
			token:   notAnObject,
			msg:     "unexpected payload",
		},
		"too long": {
			binding: bound,
			token:   strings.Repeat("A", pagetoken.MaxTokenSize+1),
			msg:     "is too long",
		},
		"empty": {
			binding: bound,
			token:   "",
			msg:     "not a token",
		},
	} {
		var got cursor
		err := pagetoken.Decode(tc.binding, tc.token, &got)
		require.ErrorIs(t, err, pagetoken.ErrInvalid, name)
		assert.ErrorContains(t, err, tc.msg, name)
	}

	_, err = pagetoken.Encode(bound, make(chan int))
	require.ErrorContains(t, err, "unable to encode page token")
}
