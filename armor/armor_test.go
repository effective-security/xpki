package armor_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/effective-security/xpki/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeAll decodes every block in data and returns the blocks and the
// final rest.
func decodeAll(t *testing.T, data []byte) ([]*armor.Block, []byte) {
	t.Helper()
	var blocks []*armor.Block
	for {
		block, rest := armor.Decode(data)
		if block == nil {
			return blocks, rest
		}
		blocks = append(blocks, block)
		require.Less(t, len(rest), len(data), "rest must shrink")
		if len(rest) == 0 {
			return blocks, rest
		}
		data = rest
	}
}

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

			blocks, rest := decodeAll(t, data)
			require.Len(t, blocks, cs.count)
			assert.Empty(t, rest)
			for _, block := range blocks {
				assert.Equal(t, "PGP PUBLIC KEY BLOCK", block.Type)
				assert.NotEmpty(t, block.Bytes)
				assert.True(t, block.HasCRC)
				assert.True(t, block.CRCValid())
				assert.Equal(t, armor.CRC24(block.Bytes), block.CRC)
			}
		})
	}
}

// Test_ArmorDecode_NoCRC decodes the two-key fixture with its checksum lines
// removed: RFC 9580 §6.1 makes the checksum optional (XPKI-047).
func Test_ArmorDecode_NoCRC(t *testing.T) {
	data, err := os.ReadFile("testdata/test-gpg-keys-2 nocrc")
	require.NoError(t, err)
	withCRC, err := os.ReadFile("testdata/test-gpg-keys-2")
	require.NoError(t, err)

	blocks, rest := decodeAll(t, data)
	require.Len(t, blocks, 2)
	assert.Empty(t, rest)
	expected, _ := decodeAll(t, withCRC)
	require.Len(t, expected, 2)
	for i, block := range blocks {
		assert.Equal(t, expected[i].Bytes, block.Bytes)
		assert.False(t, block.HasCRC)
		assert.False(t, block.CRCValid())
		assert.Zero(t, block.CRC)
	}
}

func Test_ArmorDecode_Corrupted(t *testing.T) {
	cases := []struct {
		file  string
		count int
		// crcValid is the CRCValid of each decoded block
		crcValid []bool
	}{
		{
			// checksum line "=k0GN" changed to "=k0xx": a wrong checksum
			// alone no longer rejects the block (RFC 9580 §6.1, XPKI-047)
			file:     "testdata/test-gpg-keys-2 corrupted1",
			count:    2,
			crcValid: []bool{false, true},
		},
		{
			// "___" appended to a base64 line of the second block: base64
			// failure, the block is rejected
			file:     "testdata/test-gpg-keys-2 corrupted2",
			count:    1,
			crcValid: []bool{true},
		},
		{
			// "_" appended to a base64 line of both blocks (and both
			// checksum lines malformed): base64 failure rejects both
			file:  "testdata/test-gpg-keys-2 corrupted3",
			count: 0,
		},
		{
			// truncated after a malformed checksum line: no END line
			file:  "testdata/test-gpg-keys-2 corrupted4",
			count: 0,
		},
		{
			// the file is "-----": no BEGIN line
			file:  "testdata/test-gpg-keys-2 corrupted5",
			count: 0,
		},
		{
			// "_" in the base64 data, malformed checksum, and an END line
			// with four trailing dashes: framing and base64 failures
			file:  "testdata/test-gpg-keys-2 corrupted6",
			count: 0,
		},
	}

	for _, cs := range cases {
		t.Run(cs.file, func(t *testing.T) {
			data, err := os.ReadFile(cs.file)
			require.NoError(t, err)

			blocks, _ := decodeAll(t, data)
			require.Len(t, blocks, cs.count)
			for i, block := range blocks {
				assert.Equal(t, cs.crcValid[i], block.CRCValid(), "block %d", i)
				assert.True(t, block.HasCRC, "block %d", i)
			}
		})
	}
}

// encode builds an armored block. crcLine is written verbatim after the
// data when not empty; "auto" writes the correct checksum line.
func encode(typ string, headers []string, payload []byte, crcLine string, eol string) string {
	var b strings.Builder
	b.WriteString("-----BEGIN " + typ + "-----" + eol)
	for _, h := range headers {
		b.WriteString(h + eol)
	}
	b.WriteString(eol)
	enc := base64.StdEncoding.EncodeToString(payload)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + eol)
		enc = enc[64:]
	}
	if enc != "" {
		b.WriteString(enc + eol)
	}
	if crcLine == "auto" {
		crcLine = crcString(payload)
	}
	if crcLine != "" {
		b.WriteString(crcLine + eol)
	}
	b.WriteString("-----END " + typ + "-----" + eol)
	return b.String()
}

// crcString returns the checksum line of payload.
func crcString(payload []byte) string {
	crc := armor.CRC24(payload)
	return "=" + base64.StdEncoding.EncodeToString([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)})
}

// Test_Decode_PaddingOnlyLastLine checks that a payload wrapped so that its
// last line holds only base64 padding is not mistaken for a checksum line:
// "abcd" is "YWJjZA==", wrapped after six characters.
func Test_Decode_PaddingOnlyLastLine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		hasCRC  bool
		payload string
	}{
		{name: "== line, no checksum", lines: []string{"YWJjZA", "=="}, payload: "abcd"},
		{name: "= line, no checksum", lines: []string{"YWJjZGU", "="}, payload: "abcde"},
		{name: "== line, then checksum", lines: []string{"YWJjZA", "==", crcString([]byte("abcd"))}, hasCRC: true, payload: "abcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "-----BEGIN PGP MESSAGE-----\n\n" + strings.Join(tc.lines, "\n") + "\n-----END PGP MESSAGE-----\nrest"
			block, rest := armor.Decode([]byte(text))
			require.NotNil(t, block, text)
			assert.Equal(t, tc.payload, string(block.Bytes))
			assert.Equal(t, tc.hasCRC, block.HasCRC)
			assert.Equal(t, tc.hasCRC, block.CRCValid())
			assert.Equal(t, "rest", string(rest))
		})
	}
}

func Test_CRC24(t *testing.T) {
	// the empty input leaves the initial value
	assert.Equal(t, uint32(0xb704ce), armor.CRC24(nil))
	// the fixture's checksum line
	data, err := os.ReadFile("testdata/test-gpg-keys-2")
	require.NoError(t, err)
	block, _ := armor.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "=k0GN", crcString(block.Bytes))
	assert.Equal(t, block.CRC, armor.CRC24(block.Bytes))
	var nilBlock *armor.Block
	assert.False(t, nilBlock.CRCValid())
}

// Test_Decode_Checksum covers the checksum line variants for payloads whose
// base64 has 0, 1 and 2 padding characters and that wraps over several
// lines, with LF and CRLF line endings.
func Test_Decode_Checksum(t *testing.T) {
	payloads := map[string][]byte{
		"3 bytes (no padding)": []byte("abc"),
		"4 bytes (== padding)": []byte("abcd"),
		"5 bytes (= padding)":  []byte("abcde"),
		"100 bytes (wrapped)":  bytes.Repeat([]byte{0xa5, 0x00, 0xff, 0x10}, 25),
		"empty":                {},
	}
	variants := []struct {
		name     string
		crcLine  string
		hasCRC   bool
		crcValid bool
	}{
		{name: "correct checksum", crcLine: "auto", hasCRC: true, crcValid: true},
		{name: "no checksum", crcLine: "", hasCRC: false, crcValid: false},
		{name: "wrong checksum", crcLine: "=AAAA", hasCRC: true, crcValid: false},
		{name: "short malformed checksum", crcLine: "=abc", hasCRC: false, crcValid: false},
		{name: "long malformed checksum", crcLine: "=k0GNxx", hasCRC: false, crcValid: false},
		{name: "bare equals", crcLine: "=", hasCRC: false, crcValid: false},
		{name: "checksum with trailing space", crcLine: "auto ", hasCRC: true, crcValid: true},
	}
	for name, payload := range payloads {
		for _, v := range variants {
			for _, eol := range []string{"\n", "\r\n"} {
				t.Run(name+"/"+v.name+"/"+strings.ReplaceAll(eol, "\r", "CR"), func(t *testing.T) {
					crcLine := v.crcLine
					if crcLine == "auto " {
						crcLine = crcString(payload) + " "
					}
					if crcLine == "=AAAA" && armor.CRC24(payload) == 0 {
						t.Skip("payload checksum is zero")
					}
					text := encode("PGP MESSAGE", []string{"Version: xpki", "Comment: test"}, payload, crcLine, eol)
					block, rest := armor.Decode([]byte(text + "tail"))
					require.NotNil(t, block, text)
					assert.Equal(t, "PGP MESSAGE", block.Type)
					assert.Equal(t, map[string]string{"Version": "xpki", "Comment": "test"}, block.Headers)
					assert.Equal(t, payload, block.Bytes)
					assert.Equal(t, v.hasCRC, block.HasCRC)
					assert.Equal(t, v.crcValid, block.CRCValid())
					if v.hasCRC {
						if v.crcValid {
							assert.Equal(t, armor.CRC24(payload), block.CRC)
						} else {
							assert.Zero(t, block.CRC)
						}
					} else {
						assert.Zero(t, block.CRC)
					}
					assert.Equal(t, "tail", string(rest))
				})
			}
		}
	}
}

// Test_Decode_MultipleBlocks checks that blocks with and without checksums
// decode in sequence and that rest is preserved exactly.
func Test_Decode_MultipleBlocks(t *testing.T) {
	p1, p2, p3 := []byte("first"), []byte("second block"), []byte{0, 1, 2}
	text := "# comment\n" +
		encode("PGP PUBLIC KEY BLOCK", nil, p1, "auto", "\n") +
		"between\n" +
		encode("PGP PUBLIC KEY BLOCK", nil, p2, "", "\n") +
		"\n\n" +
		encode("PGP SIGNATURE", []string{"Hash: SHA256"}, p3, "=AAAA", "\n") +
		"trailing text\n"

	block, rest := armor.Decode([]byte(text))
	require.NotNil(t, block)
	assert.Equal(t, p1, block.Bytes)
	assert.True(t, block.CRCValid())
	assert.True(t, strings.HasPrefix(string(rest), "between\n-----BEGIN"), string(rest))

	block, rest = armor.Decode(rest)
	require.NotNil(t, block)
	assert.Equal(t, p2, block.Bytes)
	assert.False(t, block.HasCRC)
	assert.Equal(t, "\n\n-----BEGIN PGP SIGNATURE-----\nHash: SHA256\n\nAAEC\n=AAAA\n-----END PGP SIGNATURE-----\ntrailing text\n", string(rest))

	block, rest = armor.Decode(rest)
	require.NotNil(t, block)
	assert.Equal(t, "PGP SIGNATURE", block.Type)
	assert.Equal(t, p3, block.Bytes)
	assert.True(t, block.HasCRC)
	assert.False(t, block.CRCValid())
	assert.Equal(t, "trailing text\n", string(rest))

	block, rest = armor.Decode(rest)
	assert.Nil(t, block)
	assert.Equal(t, "trailing text\n", string(rest))
}

// Test_Decode_Malformed checks that framing and base64 damage still rejects
// a block, and that the decoder moves on to the next valid block.
func Test_Decode_Malformed(t *testing.T) {
	good := encode("PGP MESSAGE", nil, []byte("good"), "auto", "\n")
	cases := []struct {
		name string
		text string
	}{
		{name: "equals line inside data", text: "-----BEGIN PGP MESSAGE-----\n\nYWJj\n=k0GN\nZGVm\n-----END PGP MESSAGE-----\n"},
		{name: "invalid base64", text: "-----BEGIN PGP MESSAGE-----\n\nYWJ_\n-----END PGP MESSAGE-----\n"},
		{name: "type mismatch", text: "-----BEGIN PGP MESSAGE-----\n\nYWJj\n-----END PGP SIGNATURE-----\n"},
		{name: "no end line", text: "-----BEGIN PGP MESSAGE-----\n\nYWJj\n=k0GN\n"},
		{name: "end line with four dashes", text: "-----BEGIN PGP MESSAGE-----\n\nYWJj\n-----END PGP MESSAGE----\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block, rest := armor.Decode([]byte(tc.text))
			assert.Nil(t, block)
			assert.Equal(t, tc.text, string(rest))

			// the next valid block is found
			block, rest = armor.Decode([]byte(tc.text + good))
			require.NotNil(t, block)
			assert.Equal(t, []byte("good"), block.Bytes)
			assert.True(t, block.CRCValid())
			assert.Empty(t, rest)
		})
	}
}

// Test_Decode_EmptyData checks that a block without payload decodes to
// empty bytes.
func Test_Decode_EmptyData(t *testing.T) {
	for _, text := range []string{
		"-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----\n",
		"-----BEGIN PGP MESSAGE-----\n-----END PGP MESSAGE-----\n",
		"-----BEGIN PGP MESSAGE-----\n\n" + crcString(nil) + "\n-----END PGP MESSAGE-----\n",
	} {
		block, rest := armor.Decode([]byte(text))
		require.NotNil(t, block, text)
		assert.Empty(t, block.Bytes)
		assert.Empty(t, rest)
		assert.Equal(t, strings.Contains(text, "="), block.HasCRC, text)
		assert.Equal(t, strings.Contains(text, "="), block.CRCValid(), text)
	}
}
