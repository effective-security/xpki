// Package cryptoprov provides a unified interface for cryptographic operations
// across different providers and hardware security modules (HSMs).
//
// This package abstracts cryptographic operations to support:
//   - PKCS#11 compatible HSMs via the sibling crypto11 package
//   - AWS KMS for cloud-based key management
//   - Google Cloud KMS for cloud-based key management
//   - In-memory providers for testing and development
//   - Custom providers through the Provider interface
//
// The package handles key generation, signing, encryption, and key management
// operations in a provider-agnostic way, allowing applications to switch
// between different cryptographic backends without code changes. Keys are
// RSA, ECDSA or ML-DSA (FIPS 204, post-quantum); an ML-DSA signer signs
// messages rather than digests, see MLDSASignerOptions.
//
// Configuration is a small JSON or YAML token config whose Manufacturer field
// selects a loader registered with Register; provider packages register
// themselves in init(), so import them for side effects before calling Load.
//
// A Provider creates and loads keys (KeyGenerator). A provider that is also
// a KeyManager lists its keys by page and filter, describes one with the
// fields a mask selects and destroys it; every provider of this module is
// one. A listing never returns a public key: KeyInfo does, on request.
//
//	key, err := provider.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
//		Label: "issuer-2026",
//		Type:  certutil.KeyTypeECDSA,
//		Size:  384,
//	})
//	if err != nil {
//		return err
//	}
//	keyID, _, err := provider.IdentifyKey(ctx, key)
//	if err != nil {
//		return err
//	}
//	if km, ok := provider.(cryptoprov.KeyManager); ok {
//		info, err := km.KeyInfo(ctx, keyID, cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldPublicKey)
//		if err != nil {
//			return err
//		}
//		fmt.Println(info.Label, info.Type, info.Size, info.PublicKey)
//	}
package cryptoprov
