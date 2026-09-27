// Package armor implements OpenPGP ASCII Armor, see RFC 9580 §6. OpenPGP
// Armor is very similar to PEM except that it may carry a CRC24 checksum
// line before the end line. The checksum is optional and Decode never
// rejects a block because of it (RFC 9580 §6.1); Block.CRCValid reports
// whether a present checksum matches the decoded bytes.
package armor

import (
	"bytes"
	"encoding/base64"

	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "armor")

// A Block represents an OpenPGP armored structure.
//
// The encoded form is:
//
//	-----BEGIN Type-----
//	Headers
//
//	base64-encoded Bytes
//	'=' base64 encoded checksum (optional)
//	-----END Type-----
//
// where Headers is a possibly empty sequence of Key: Value lines.
type Block struct {
	Type    string            // The type, taken from the preamble (i.e. "RSA PRIVATE KEY").
	Headers map[string]string // Optional headers.
	Bytes   []byte            // The decoded bytes of the contents. Typically a DER encoded ASN.1 structure.
	// CRC is the CRC24 checksum from the checksum line. It is meaningful
	// only when HasCRC is set.
	CRC uint32
	// HasCRC reports whether the block had a well-formed checksum line: "="
	// followed by four base64 characters. Decode accepts a block without it,
	// with a malformed one (HasCRC is false) and with a wrong one (HasCRC is
	// true and CRCValid is false), as RFC 9580 §6.1 asks; callers that want
	// the checksum enforced check CRCValid.
	HasCRC bool
}

// CRCValid reports whether the block has a checksum line and its value
// matches the CRC24 of Bytes.
func (b *Block) CRCValid() bool {
	return b != nil && b.HasCRC && b.CRC == CRC24(b.Bytes)
}

// getLine results the first \r\n or \n delineated line from the given byte
// array. The line does not include trailing whitespace or the trailing new
// line bytes. The remainder of the byte array (also not including the new line
// bytes) is also returned and this will always be smaller than the original
// argument.
func getLine(data []byte) (line, rest []byte) {
	i := bytes.IndexByte(data, '\n')
	var j int
	if i < 0 {
		i = len(data)
		j = i
	} else {
		j = i + 1
		if i > 0 && data[i-1] == '\r' {
			i--
		}
	}
	return bytes.TrimRight(data[0:i], " \t"), data[j:]
}

// removeWhitespace returns a copy of its input with all spaces, tab and
// newline characters removed.
func removeWhitespace(data []byte) []byte {
	result := make([]byte, len(data))
	n := 0

	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		result[n] = b
		n++
	}

	return result[0:n]
}

var pemStart = []byte("\n-----BEGIN ")
var pemEnd = []byte("\n-----END ")
var pemEndOfLine = []byte("-----")

// Decode will find the next armored block in the input. It returns that
// block and the remainder of the input. If no armored data is found, p is
// nil and the whole of the input is returned in rest. A block whose framing
// or base64 data is malformed is skipped. The checksum line is optional and
// never causes a block to be skipped; see Block.HasCRC and Block.CRCValid.
func Decode(data []byte) (p *Block, rest []byte) {
	var err error
	// pemStart begins with a newline. However, at the very beginning of
	// the byte array, we'll accept the start string without it.
	rest = data
	if bytes.HasPrefix(data, pemStart[1:]) {
		rest = rest[len(pemStart)-1 : len(data)]
	} else if i := bytes.Index(data, pemStart); i >= 0 {
		rest = rest[i+len(pemStart) : len(data)]
	} else {
		logger.KV(xlog.DEBUG, "reason", "prefix_not_found")
		return nil, data
	}

	typeLine, rest := getLine(rest)
	if !bytes.HasSuffix(typeLine, pemEndOfLine) {
		logger.KV(xlog.DEBUG, "reason", "sufix_not_found")
		return decodeError(data, rest)
	}
	typeLine = typeLine[0 : len(typeLine)-len(pemEndOfLine)]

	p = &Block{
		Headers: make(map[string]string),
		Type:    string(typeLine),
	}

	for {
		// This loop terminates because getLine's second result is
		// always smaller than its argument.
		if len(rest) == 0 {
			return nil, data
		}
		line, next := getLine(rest)

		i := bytes.IndexByte(line, ':')
		if i == -1 {
			break
		}

		// TODO(agl): need to cope with values that spread across lines.
		key, val := line[:i], line[i+1:]
		key = bytes.TrimSpace(key)
		val = bytes.TrimSpace(val)
		p.Headers[string(key)] = string(val)
		rest = next
	}

	var endIndex, endTrailerIndex int

	// If there were no headers, the END line might occur
	// immediately, without a leading newline.
	if len(p.Headers) == 0 && bytes.HasPrefix(rest, pemEnd[1:]) {
		endIndex = 0
		endTrailerIndex = len(pemEnd) - 1
	} else {
		endIndex = bytes.Index(rest, pemEnd)
		endTrailerIndex = endIndex + len(pemEnd)
	}

	if endIndex < 0 {
		logger.KV(xlog.DEBUG, "reason", "end_index", "index", endIndex)
		return decodeError(data, rest)
	}

	// After the "-----" of the ending line, there should be the same type
	// and then a final five dashes.
	endTrailer := rest[endTrailerIndex:]
	endTrailerLen := len(typeLine) + len(pemEndOfLine)
	if len(endTrailer) < endTrailerLen {
		logger.KV(xlog.DEBUG, "reason", "end_trailer", "trailerLen", endTrailerLen)
		return decodeError(data, rest)
	}

	restOfEndLine := endTrailer[endTrailerLen:]
	endTrailer = endTrailer[:endTrailerLen]
	if !bytes.HasPrefix(endTrailer, typeLine) ||
		!bytes.HasSuffix(endTrailer, pemEndOfLine) {
		return decodeError(data, rest)
	}

	// The line must end with only whitespace.
	if s, _ := getLine(restOfEndLine); len(s) != 0 {
		return decodeError(data, rest)
	}

	// The data region is the base64 payload, optionally followed by the
	// checksum line: "=" and four base64 characters (RFC 9580 §6.1). Only
	// the last non-empty line can be the checksum line; a "=" line anywhere
	// else is part of the payload and fails the base64 decoding below.
	base64Data, crcLine := splitChecksumLine(rest[:endIndex])

	p.Bytes, err = decodeBase64(base64Data)
	if err != nil && crcLine != nil {
		// A last line made of "=" only may be the padding of a payload
		// wrapped just before it rather than a checksum line: decode again
		// with the line as payload before giving up.
		if withLine, lerr := decodeBase64(append(base64Data, removeWhitespace(crcLine)...)); lerr == nil {
			p.Bytes, err, crcLine = withLine, nil, nil
		}
	}
	if err != nil {
		logger.KV(xlog.DEBUG, "reason", "base64", "err", err)
		return decodeError(data, rest)
	}

	if crcLine != nil {
		if crc, ok := parseChecksumLine(crcLine); ok {
			p.HasCRC = true
			p.CRC = crc
		} else {
			// a malformed checksum does not reject the block
			logger.KV(xlog.DEBUG, "reason", "malformed_crc", "len", len(crcLine))
		}
	}

	if p.HasCRC {
		if crc := CRC24(p.Bytes); p.CRC != crc {
			// a wrong checksum does not reject the block either
			logger.KV(xlog.DEBUG, "reason", "crc_mismatch", "expected", p.CRC, "actual", crc)
		}
	}

	// the -1 is because we might have only matched pemEnd without the
	// leading newline if the PEM block was empty.
	_, rest = getLine(rest[endIndex+len(pemEnd)-1:])

	return
}

func decodeError(data, rest []byte) (*Block, []byte) {
	// If we get here then we have rejected a likely looking, but
	// ultimately invalid PEM block. We need to start over from a new
	// position. We have consumed the preamble line and will have consumed
	// any lines which could be header lines. However, a valid preamble
	// line is not a valid header line, therefore we cannot have consumed
	// the preamble line for the any subsequent block. Thus, we will always
	// find any valid block, no matter what bytes precede it.
	//
	// For example, if the input is
	//
	//    -----BEGIN MALFORMED BLOCK-----
	//    junk that may look like header lines
	//   or data lines, but no END line
	//
	//    -----BEGIN ACTUAL BLOCK-----
	//    realdata
	//    -----END ACTUAL BLOCK-----
	//
	// we've failed to parse using the first BEGIN line
	// and now will try again, using the second BEGIN line.
	p, rest := Decode(rest)
	if p == nil {
		rest = data
	}
	return p, rest
}

// decodeBase64 decodes the whitespace-free base64 payload of a block.
func decodeBase64(base64Data []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(base64Data)))
	n, err := base64.StdEncoding.Decode(out, base64Data)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

// splitChecksumLine splits the data region of a block into its base64
// payload, with whitespace removed, and its checksum line: the last
// non-empty line when it starts with "=", trimmed, else nil. Decode keeps
// the line as payload instead when the payload does not decode without it,
// since a wrapped payload may end with a line of padding only.
func splitChecksumLine(region []byte) (base64Data, crcLine []byte) {
	trimmed := bytes.TrimRight(region, " \t\r\n")
	start := bytes.LastIndexByte(trimmed, '\n') + 1
	if last := bytes.TrimSpace(trimmed[start:]); len(last) > 0 && last[0] == '=' {
		return removeWhitespace(trimmed[:start]), last
	}
	return removeWhitespace(trimmed), nil
}

// parseChecksumLine decodes a checksum line: "=" and four base64
// characters holding the CRC24 in three bytes.
func parseChecksumLine(line []byte) (uint32, bool) {
	if len(line) != 5 {
		return 0, false
	}
	var crc [3]byte
	n, err := base64.StdEncoding.Decode(crc[:], line[1:])
	if err != nil || n != 3 {
		return 0, false
	}
	return uint32(crc[0])<<16 | uint32(crc[1])<<8 | uint32(crc[2]), true
}

const crc24Init = 0xb704ce
const crc24Poly = 0x1864cfb
const crc24Mask = 0xffffff

// CRC24 returns the OpenPGP checksum of data, as specified in RFC 9580,
// section 6.1. It is the value carried by the armor checksum line.
func CRC24(data []byte) uint32 {
	return crc24(crc24Init, data) & crc24Mask
}

// crc24 calculates the OpenPGP checksum as specified in RFC 9580, section 6.1
func crc24(crc uint32, d []byte) uint32 {
	for _, b := range d {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= crc24Poly
			}
		}
	}
	return crc
}
