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
	assert.EqualError(t, err, "failed to upprotect: cipher: message authentication failed")

	_, err = p.Unprotect(ctx, nil)
	assert.EqualError(t, err, "invalid data")

	_, err = p.Unprotect(ctx, protected[:11])
	assert.EqualError(t, err, "invalid data")
}
