package crypto11

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GenerateKeyID(t *testing.T) {
	id, err := p11lib.generateKeyID()
	require.NoError(t, err)
	assert.Equal(t, 32, len(id))
}

func Test_GenerateKeyLabel(t *testing.T) {
	label, err := p11lib.generateKeyLabel()
	require.NoError(t, err)
	assert.Equal(t, 32, len(label))

	now := time.Now().UTC()
	prefix := fmt.Sprintf("%04d%02d%02d%02d%02d%02d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	assert.True(t, strings.HasPrefix(string(label), prefix), "Key should have prefix %q, got %q", prefix, label)
}

func Test_dsaSignature_unmarshalBytes(t *testing.T) {
	tcases := []struct {
		name string
		in   []byte
		err  error
	}{
		{name: "empty", in: nil, err: errMalformedSignature},
		{name: "odd", in: []byte{1, 2, 3}, err: errMalformedSignature},
		{name: "even", in: []byte{0, 1, 0, 2}, err: nil},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			var sig dsaSignature
			err := sig.unmarshalBytes(tc.in)
			if tc.err != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.err), "got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int64(1), sig.R.Int64())
			assert.Equal(t, int64(2), sig.S.Int64())
		})
	}
}
