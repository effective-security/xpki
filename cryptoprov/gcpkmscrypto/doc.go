// Package gcpkmscrypto implements cryptoprov.Provider and cryptoprov.KeyManager
// over Google Cloud KMS (HSM protection level). It registers itself as
// manufacturer "GCPKMS"; the token config Attributes field must carry
// "Keyring=projects/P/locations/L/keyRings/R". Authentication uses
// Application Default Credentials. Call Close to release the gRPC client.
package gcpkmscrypto
