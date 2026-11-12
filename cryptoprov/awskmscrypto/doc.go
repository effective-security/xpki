// Package awskmscrypto implements cryptoprov.Provider and cryptoprov.KeyManager
// over AWS KMS asymmetric signing keys (RSA 2048/3072/4096, NIST P-256,
// P-384, P-521 and ML-DSA-44/65/87). It registers itself as manufacturer
// "AWSKMS". Credentials, the default region and retries come from the
// default AWS SDK chain. Keys never leave KMS: ExportKey returns a pkcs11:
// URI and Sign calls kms:Sign with a digest, after checking the options
// against the algorithms KMS reports for the key. Encryption keys
// (cryptoprov.KeyUsageEncrypt, ENCRYPT_DECRYPT) are not supported.
//
// The token config Attributes field carries comma separated "Name=value"
// settings, all optional:
//
//   - Endpoint=<url> and Region=<region> select the KMS endpoint;
//   - TagSearch=true answers a tag filter with the Resource Groups Tagging
//     API and makes GenerateKey write the xpki-label, xpki-type, xpki-size
//     and xpki-usage tags (TaggingEndpoint=<url> is the endpoint of that
//     API). It needs tag:GetResources and kms:TagResource;
//   - LabelSearch=scan makes a label filter describe every key and match
//     its description, instead of looking the label up through its alias;
//   - DescribeConcurrency=<n> is the number of per-key requests a listing
//     has in flight at once (1 to 64, default 8);
//   - MetadataCacheSize=<n> is the number of keys whose immutable metadata
//     the provider remembers (default 50000, 0 disables).
//
// ListKeys needs kms:ListKeys, kms:DescribeKey and kms:ListAliases, and
// kms:ListResourceTags when it reads tags without TagSearch. KMS has no
// search: Provider.ListKeys describes how a listing narrows its candidates
// (the alias of a label, the tagging API, cached key metadata) before it
// describes a key, and what each filter costs.
//
//	req := &cryptoprov.ListKeysRequest{
//		Filter: cryptoprov.KeyFilter{
//			LabelPrefix: "issuer-",
//			Usage:       cryptoprov.KeyUsageSign,
//		},
//		Fields: cryptoprov.KeyFieldMetadata,
//	}
//	for key, err := range cryptoprov.AllKeys(ctx, provider, req) {
//		if err != nil {
//			return err
//		}
//		fmt.Println(key.ID, key.Label, key.Type, key.Size)
//	}
package awskmscrypto
