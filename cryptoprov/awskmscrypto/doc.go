// Package awskmscrypto implements cryptoprov.Provider and cryptoprov.KeyManager
// over AWS KMS asymmetric signing keys (RSA 2048/3072/4096 and NIST P-256,
// P-384, P-521). It registers itself as manufacturer "AWSKMS"; the token
// config Attributes field carries "Endpoint=<url>,Region=<region>", both
// optional. Credentials, the default region and retries come from the
// default AWS SDK chain. Keys never leave KMS: ExportKey returns a pkcs11:
// URI and Sign calls kms:Sign with a digest, after checking the options
// against the algorithms KMS reports for the key. EnumKeys needs
// kms:ListKeys and kms:DescribeKey on every key it lists. Encryption keys
// (GenerateRSAKey purpose 2, ENCRYPT_DECRYPT) are not supported.
package awskmscrypto
