// Package gcpkmscrypto implements cryptoprov.Provider and cryptoprov.KeyManager
// over Google Cloud KMS (HSM protection level). It registers itself as
// manufacturer "GCPKMS"; the token config Attributes field must carry
// "Keyring=projects/P/locations/L/keyRings/R" and may carry
// "Endpoint=host:port" for a non-default API endpoint. Authentication uses
// Application Default Credentials. Call Close to release the gRPC client.
//
// Keys are ASYMMETRIC_SIGN keys. A key ID is a CryptoKey id, "K", or one of
// its versions, "K/cryptoKeyVersions/N". Generated and loaded signers name
// their version, so the URI from ExportKey pins it. A bare id is resolved
// at each call: GetKey uses the newest enabled version, KeyInfo the newest
// enabled or else the newest non-destroyed version, and
// DestroyKey every enabled or disabled version. Sign accepts only
// the hash and padding of the version's KMS algorithm.
//
// GenerateKey creates HSM keys only. An algorithm that Cloud KMS does not
// offer at that protection level fails with an error that is
// cryptoprov.ErrNotSupported and keeps the KMS status: on 2026-11-12 that
// was every ML-DSA algorithm, which Cloud KMS listed for software keys only.
// GetKey does not look at the protection level of the key it loads.
//
// The label of a key is its "label" label and its tags are its labels.
// ListKeys is one ListCryptoKeys request for a full page: label and tag
// conditions are sent to KMS as a filter and every condition is checked
// again on the returned keys. The state of an asymmetric key is the state of
// a version, which costs a request per key, so a listing reads it only for
// cryptoprov.KeyFieldState or a filter on states.
package gcpkmscrypto
