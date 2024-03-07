package dataprotection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSymmetric(t *testing.T) {
	p, err := NewSymmetric([]byte("secret"))
	require.NoError(t, err)
	assert.True(t, p.IsReady())
	assert.Nil(t, p.PublicKey())

	plaintext := []byte(`small data`)
	ctx := context.Background()
	protected, err := p.Protect(ctx, plaintext)
	require.NoError(t, err)

	unprotected, err := p.Unprotect(ctx, protected)
	require.NoError(t, err)
	assert.Equal(t, plaintext, unprotected)

	// modify the data
	protected[0] = protected[1]
	_, err = p.Unprotect(ctx, protected)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")

	_, err = p.Unprotect(ctx, nil)
	assert.EqualError(t, err, "invalid data: less than nonce size")

	_, err = p.Unprotect(ctx, protected[:11])
	assert.EqualError(t, err, "invalid data: less than nonce size")

	s := state{Str: "hello", ID: 123}
	b64, err := ProtectObject(ctx, p, s)
	require.NoError(t, err)
	var s2 state
	err = UnprotectObject(ctx, p, b64, &s2)
	require.NoError(t, err)
	assert.Equal(t, s, s2)

	err = UnprotectObject(ctx, p, "b64", &s2)
	assert.EqualError(t, err, "invalid data: less than nonce size")

	err = UnprotectObject(ctx, p, "Aa"+b64, &s2)
	assert.EqualError(t, err, "failed to unprotect: cipher: message authentication failed")
}

type state struct {
	Str string `json:"str,omitempty"`
	ID  uint64 `json:"id,omitempty"`
}
