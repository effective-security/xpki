// Package awskmscrypto implements cryptoprov.Provider and cryptoprov.KeyManager
// over AWS KMS asymmetric keys. It registers itself as manufacturer "AWSKMS";
// the token config Attributes field carries "Endpoint=<url>,Region=<region>".
// Credentials come from the default AWS SDK chain. Keys never leave KMS:
// ExportKey returns a pkcs11: URI and Sign calls kms:Sign with a digest.
package awskmscrypto
