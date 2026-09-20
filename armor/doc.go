// Package armor decodes OpenPGP ASCII-armored blocks (RFC 4880/9580):
// PEM-like text with a BEGIN/END frame, optional headers, a base64 body and
// a CRC24 trailer. Only decoding is provided; malformed blocks are skipped
// and the decoder resumes at the next BEGIN line.
package armor
