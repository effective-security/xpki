package crypto11

import (
	"fmt"
	"strconv"
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

// miekgUlong encodes n the way miekg/pkcs11 builds CK_ULONG attributes, as a
// reference independent of UlongToBytes.
func miekgUlong(n uint) []byte {
	return pkcs11.NewAttribute(pkcs11.CKA_CLASS, n).Value
}

func Test_bytesToUlong_Malformed(t *testing.T) {
	t.Parallel()
	// distinct bytes past each input, so an out-of-bounds read would decode
	// them instead of failing
	buf := make([]byte, 2*ulongSize+1)
	for i := range buf {
		buf[i] = byte(i + 1)
	}
	tcs := []struct {
		name string
		in   []byte
	}{
		{name: "nil", in: nil},
		{name: "empty", in: []byte{}},
		{name: "one byte", in: buf[:1]},
		{name: "one short", in: buf[:ulongSize-1]},
		{name: "one long", in: buf[:ulongSize+1]},
		{name: "two values", in: buf[:2*ulongSize]},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := bytesToUlong(tc.in)
			require.ErrorIs(t, err, errMalformedUlong)
			assert.EqualError(t, err, fmt.Sprintf("length %d, expected %d: crypto11: malformed CK_ULONG attribute value", len(tc.in), ulongSize))
			assert.Zero(t, n)

			assert.NotPanics(t, func() {
				n = BytesToUlong(tc.in)
			})
			assert.Equal(t, unavailableInformation, n)
		})
	}
}

func Test_bytesToUlong_RoundTrip(t *testing.T) {
	t.Parallel()
	assert.Len(t, miekgUlong(0), ulongSize, "CK_ULONG width differs from miekg/pkcs11")

	// the largest CK_ULONG, 32 bits where C unsigned long is 32 bits
	maxUlong := ^uint(0) >> (strconv.IntSize - 8*ulongSize)
	values := []uint{
		pkcs11.CKK_RSA,
		pkcs11.CKK_EC,
		pkcs11.CKO_PRIVATE_KEY,
		pkcs11.CKK_VENDOR_DEFINED,
		0x01020304,
		maxUlong,
	}
	for _, v := range values {
		t.Run(fmt.Sprintf("%#x", v), func(t *testing.T) {
			t.Parallel()
			ref := miekgUlong(v)
			assert.Equal(t, ref, UlongToBytes(v))

			n, err := bytesToUlong(ref)
			require.NoError(t, err)
			assert.Equal(t, v, n)
			assert.Equal(t, v, BytesToUlong(ref))
		})
	}
}

func Test_keyTypeAndClass(t *testing.T) {
	t.Parallel()
	attr := func(typ, v uint) *pkcs11.Attribute {
		return pkcs11.NewAttribute(typ, v)
	}
	malformed := &pkcs11.Attribute{
		Type:  pkcs11.CKA_CLASS,
		Value: []byte{1},
	}

	keyType, class, err := keyTypeAndClass(attr(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC), attr(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", keyType)
	assert.Equal(t, "Private key", class)

	// CKK_RSA and CKO_DATA are zero, so a zero default must not be mistaken for them
	keyType, class, err = keyTypeAndClass(attr(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA), attr(pkcs11.CKA_CLASS, pkcs11.CKO_DATA))
	require.NoError(t, err)
	assert.Equal(t, "RSA", keyType)
	assert.Equal(t, "Data", class)

	keyType, class, err = keyTypeAndClass(attr(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_VENDOR_DEFINED), attr(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
	require.NoError(t, err)
	assert.Empty(t, keyType)
	assert.Equal(t, "Public key", class)

	_, _, err = keyTypeAndClass(&pkcs11.Attribute{Type: pkcs11.CKA_KEY_TYPE}, attr(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
	require.ErrorIs(t, err, errMalformedUlong)
	assert.EqualError(t, err, fmt.Sprintf("CKA_KEY_TYPE: length 0, expected %d: crypto11: malformed CK_ULONG attribute value", ulongSize))

	_, _, err = keyTypeAndClass(attr(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC), malformed)
	require.ErrorIs(t, err, errMalformedUlong)
	assert.EqualError(t, err, fmt.Sprintf("CKA_CLASS: length 1, expected %d: crypto11: malformed CK_ULONG attribute value", ulongSize))
}
