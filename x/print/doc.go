// Package print writes human-readable descriptions of certificates,
// certificate requests, CRLs and OCSP responses to an io.Writer, and a JSON
// helper for CLI output. Timestamps are printed in local time; write errors
// are ignored by design because the output is for humans.
package print
