package crypto11

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GenerateKeyID(t *testing.T) {
	requireP11(t)
	var id []byte
	err := p11lib.withSession(p11lib.Slot.id, func(session pkcs11.SessionHandle) error {
		var err error
		id, err = p11lib.generateKeyID(session)
		return err
	})
	require.NoError(t, err)
	assert.Equal(t, 32, len(id))

	_, err = p11lib.generateKeyID(0)
	assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
}

func Test_GenerateKeyLabel(t *testing.T) {
	requireP11(t)
	var label []byte
	err := p11lib.withSession(p11lib.Slot.id, func(session pkcs11.SessionHandle) error {
		var err error
		label, err = p11lib.generateKeyLabel(session)
		return err
	})
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
