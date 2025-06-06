package crypto11

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/miekg/pkcs11"
)

func init() {
	_ = cryptoprov.Register("SoftHSM", LoadProvider)
}

// LoadProvider provides loader for crypto11 provider
func LoadProvider(cfg cryptoprov.TokenConfig) (cryptoprov.Provider, error) {
	p, err := Init(cfg)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Ensure compiles
var _ cryptoprov.Provider = (*PKCS11Lib)(nil)
var _ cryptoprov.KeyManager = (*PKCS11Lib)(nil)

// EnumTokens enumerates tokens
func (lib *PKCS11Lib) EnumTokens(currentSlotOnly bool) ([]cryptoprov.TokenInfo, error) {
	if currentSlotOnly {
		return []cryptoprov.TokenInfo{
			{
				SlotID:       lib.Slot.id,
				Description:  lib.Slot.description,
				Label:        lib.Slot.label,
				Manufacturer: lib.Slot.manufacturer,
				Model:        lib.Slot.model,
				Serial:       lib.Slot.serial,
			},
		}, nil
	}

	list, err := lib.TokensInfo()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	res := make([]cryptoprov.TokenInfo, len(list))
	for i, ti := range list {
		res[i].SlotID = ti.id
		res[i].Description = ti.description
		res[i].Label = ti.label
		res[i].Manufacturer = ti.manufacturer
		res[i].Model = ti.model
		res[i].Serial = ti.serial
	}
	return res, nil
}

// EnumKeys returns lists of keys on the slot
func (lib *PKCS11Lib) EnumKeys(slotID uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	sh, err := lib.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, errors.WithMessagef(err, "OpenSession on slot %d", slotID)
	}
	defer func() {
		_ = lib.Ctx.CloseSession(sh)
	}()

	keys, err := lib.ListKeys(sh, pkcs11.CKO_PRIVATE_KEY, ^uint(0))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := make([]cryptoprov.KeyInfo, 0, len(keys))
	for _, obj := range keys {
		attributes := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
		}
		if attributes, err = lib.Ctx.GetAttributeValue(sh, obj, attributes); err != nil {
			return nil, errors.WithMessagef(err, "GetAttributeValue on key")
		}

		keyLabel := string(attributes[1].Value)
		if prefix != "" && !strings.HasPrefix(keyLabel, prefix) {
			continue
		}
		res = append(res, cryptoprov.KeyInfo{
			ID:    string(attributes[0].Value),
			Label: keyLabel,
			Type:  KeyTypeNames[BytesToUlong(attributes[2].Value)],
			Class: ObjectClassNames[BytesToUlong(attributes[3].Value)],
		})
	}

	return res, nil
}

// KeyInfo retrieves info about key with the specified id
func (lib *PKCS11Lib) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	var err error
	session, err := lib.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, errors.WithMessagef(err, "OpenSession on slot %d", slotID)
	}
	defer func() {
		_ = lib.Ctx.CloseSession(session)
	}()

	var privHandle pkcs11.ObjectHandle
	if privHandle, err = lib.findKey(session, keyID, "", pkcs11.CKO_PRIVATE_KEY, ^uint(0)); err != nil {
		logger.KV(xlog.WARNING, "reason", "not_found", "type", "CKO_PRIVATE_KEY", "err", err.Error())
	}

	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
	}
	if attributes, err = lib.Ctx.GetAttributeValue(session, privHandle, attributes); err != nil {
		return nil, errors.WithMessagef(err, "GetAttributeValue on key")
	}

	keyLabel := string(attributes[1].Value)
	keyID = string(attributes[0].Value)

	pubKey := ""
	if includePublic {
		pubKey, err = lib.getPublicKeyPEM(slotID, keyID)
		if err != nil {
			return nil, errors.WithMessagef(err, "reason='failed on GetPublicKey', slotID=%d, keyID=%q", slotID, keyID)
		}
	}

	return &cryptoprov.KeyInfo{
		ID:        keyID,
		Label:     keyLabel,
		Type:      KeyTypeNames[BytesToUlong(attributes[2].Value)],
		Class:     ObjectClassNames[BytesToUlong(attributes[3].Value)],
		PublicKey: pubKey,
	}, nil
}
