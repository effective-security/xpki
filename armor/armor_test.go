package armor_test

import (
	"os"
	"testing"

	"github.com/effective-security/xpki/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ArmorDecode(t *testing.T) {
	cases := []struct {
		file  string
		count int
	}{
		{
			file:  "testdata/RPM-GPG-KEY-CentOS-7",
			count: 1,
		},
		{
			file:  "testdata/test-gpg-keys-2",
			count: 2,
		},
	}

	for _, cs := range cases {
		t.Run(cs.file, func(t *testing.T) {
			data, err := os.ReadFile(cs.file)
			require.NoError(t, err)

			count := 0
			for {
				block, rest := armor.Decode(data)
				require.NotNil(t, block)
				count++

				if len(rest) == 0 {
					break
				}
				data = rest
			}

			assert.Equal(t, cs.count, count)
		})
	}
}

func Test_ArmorDecode_Corrupted(t *testing.T) {
	cases := []struct {
		file  string
		count int
	}{
		{
			file:  "testdata/test-gpg-keys-2 corrupted1",
			count: 1,
		},
		{
			file:  "testdata/test-gpg-keys-2 corrupted2",
			count: 1,
		},
		{
			file:  "testdata/test-gpg-keys-2 corrupted3",
			count: 0,
		},
		{
			file:  "testdata/test-gpg-keys-2 corrupted4",
			count: 0,
		},
		{
			file:  "testdata/test-gpg-keys-2 corrupted5",
			count: 0,
		},
		{
			file:  "testdata/test-gpg-keys-2 corrupted6",
			count: 0,
		},
	}

	for _, cs := range cases {
		t.Run(cs.file, func(t *testing.T) {
			data, err := os.ReadFile(cs.file)
			require.NoError(t, err)

			count := 0
			for {
				block, rest := armor.Decode(data)
				if block == nil {
					break
				}
				count++

				if len(rest) == 0 {
					break
				}
				data = rest
			}

			assert.Equal(t, cs.count, count)
		})
	}
}
