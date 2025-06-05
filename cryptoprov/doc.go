// Package cryptoprov provides a unified interface for cryptographic operations
// across different providers and hardware security modules (HSMs).
//
// This package abstracts cryptographic operations to support:
//   - PKCS#11 compatible HSMs via the crypto11 subpackage
//   - AWS KMS for cloud-based key management
//   - Google Cloud KMS for cloud-based key management
//   - In-memory providers for testing and development
//   - Custom providers through the Provider interface
//
// The package handles key generation, signing, encryption, and key management
// operations in a provider-agnostic way, allowing applications to switch
// between different cryptographic backends without code changes.
//
// Configuration is typically done through YAML files that specify the
// provider type and its specific settings.
package cryptoprov
