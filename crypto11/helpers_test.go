package crypto11

import (
	"context"

	"github.com/effective-security/xpki/v2/cryptoprov"
)

// keyFields are the groups a v1 KeyInfo filled, and keyFieldsPublic the same
// with the public key.
const (
	keyFields       = cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState
	keyFieldsPublic = keyFields | cryptoprov.KeyFieldPublicKey
)

// enumKeys lists every private key on slot whose label starts with prefix,
// with the Metadata group: the listing a v1 EnumKeys returned. It reads the
// largest page, so that a token other tests change is listed in as few
// calls as possible.
func enumKeys(lib *PKCS11Lib, slot uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	req := &cryptoprov.ListKeysRequest{
		PageSize: cryptoprov.MaxPageSize,
		Filter:   cryptoprov.KeyFilter{LabelPrefix: prefix},
		Fields:   cryptoprov.KeyFieldMetadata,
	}
	keys := []cryptoprov.KeyInfo{}
	for {
		resp, err := lib.listKeysOnSlot(context.Background(), slot, req)
		if err != nil {
			return nil, err
		}
		keys = append(keys, resp.Keys...)
		if resp.NextPageToken == "" {
			return keys, nil
		}
		req.PageToken = resp.NextPageToken
	}
}
