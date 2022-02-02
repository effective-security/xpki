package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
)

// VersionFlag is a flag to print version
type VersionFlag string

// Decode the flag
func (v VersionFlag) Decode(ctx *kong.DecodeContext) error { return nil }

// IsBool returns true for the flag
func (v VersionFlag) IsBool() bool { return true }

// BeforeApply is executed before context is applied
func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Fprintln(app.Stdout, v)
	app.Exit(0)
	return nil
}

var (
	// jsonEncPPHandle is used to encode json with a human readable pretty printed out put, as well as
	// line breaks/indents, fields are serialized in a canonical order everytime
	jsonEncPPHandle codec.JsonHandle
)

func init() {
	jsonEncPPHandle.BasicHandle.EncodeOptions.Canonical = true
	jsonEncPPHandle.Indent = -1
}

var newLine = []byte("\n")

// WriteJSON prints response to out
func WriteJSON(out io.Writer, value interface{}) error {
	var json []byte
	err := codec.NewEncoderBytes(&json, &jsonEncPPHandle).Encode(value)
	if err != nil {
		return errors.WithMessage(err, "failed to encode")
	}

	out.Write(json)
	out.Write(newLine)

	return nil
}

// FileExists ensures that file exists
func FileExists(file string) error {
	if file == "" {
		return errors.Errorf("invalid parameter: file")
	}

	stat, err := os.Stat(file)
	if err != nil {
		return errors.WithStack(err)
	}

	if stat.IsDir() {
		return errors.Errorf("not a file: %s", file)
	}

	return nil
}

// WriteCert outputs a cert, key and csr
func WriteCert(w io.Writer, key, csrBytes, cert []byte) {
	out := map[string]string{}
	if cert != nil {
		out["cert"] = string(cert)
	}

	if key != nil {
		out["key"] = string(key)
	}

	if csrBytes != nil {
		out["csr"] = string(csrBytes)
	}

	jsonOut, _ := json.Marshal(out)
	fmt.Fprintln(w, string(jsonOut))
}
