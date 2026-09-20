// Package cli implements the hsm-tool command tree: hsm list/info/generate/
// remove and csr create/gen-cert/sign. Providers are registered by blank
// imports and loaded lazily from the --cfg and --crypto config files.
package cli
