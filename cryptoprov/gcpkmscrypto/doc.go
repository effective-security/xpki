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
// DestroyKeyPairOnSlot every enabled or disabled version. Sign accepts only
// the hash and padding of the version's KMS algorithm.
package gcpkmscrypto
