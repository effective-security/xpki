package crypto11

import (
	"strings"

	"github.com/effective-security/xpki/certutil"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// CurrentSlotID returns current slot ID
func (p11lib *PKCS11Lib) CurrentSlotID() uint {
	return p11lib.Slot.id
}

// TokensInfo returns list of tokens
func (p11lib *PKCS11Lib) TokensInfo() ([]*SlotTokenInfo, error) {
	list := []*SlotTokenInfo{}
	slots, err := p11lib.Ctx.GetSlotList(true)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	logger.Tracef("slots=%d", len(slots))

	for _, slotID := range slots {
		si, err := p11lib.Ctx.GetSlotInfo(slotID)
		if err != nil {
			return nil, errors.WithMessagef(err, "GetSlotInfo: %d", slotID)
		}
		ti, err := p11lib.Ctx.GetTokenInfo(slotID)
		if err != nil {
			logger.Errorf(
				"reason=GetTokenInfo, slotID=%d, ManufacturerID=%q, SlotDescription=%q, err=[%+v]",
				slotID,
				si.ManufacturerID,
				si.SlotDescription,
				err,
			)
		} else if ti.SerialNumber != "" || ti.Label != "" {
			list = append(list, &SlotTokenInfo{
				id:           slotID,
				description:  si.SlotDescription,
				label:        ti.Label,
				manufacturer: strings.TrimSpace(ti.ManufacturerID),
				model:        strings.TrimSpace(ti.Model),
				serial:       ti.SerialNumber,
				flags:        ti.Flags,
			})

		}
	}
	return list, nil
}

// DestroyKeyPairOnSlot destroys key pair
func (p11lib *PKCS11Lib) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	var err error
	session, err := p11lib.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return errors.WithMessagef(err, "OpenSession on slot %d", slotID)
	}
	defer p11lib.Ctx.CloseSession(session)

	logger.Tracef("slot=0x%X, id=%q", slotID, keyID)

	id := []byte(keyID)

	var privHandle, pubHandle pkcs11.ObjectHandle
	if privHandle, err = p11lib.findKey(session, keyID, "", pkcs11.CKO_PRIVATE_KEY, ^uint(0)); err != nil {
		logger.Warningf("reason=not_found, type=CKO_PRIVATE_KEY, err=[%+v]", err)
	}
	if pubHandle, err = p11lib.findKey(session, keyID, "", pkcs11.CKO_PUBLIC_KEY, ^uint(0)); err != nil {
		logger.Warningf("reason=not_found, type=CKO_PUBLIC_KEY, err=[%+v]", err)
	}

	if privHandle != 0 {
		err = p11lib.Ctx.DestroyObject(session, privHandle)
		if err != nil {
			return errors.WithStack(err)
		}
		logger.Infof("type=CKO_PRIVATE_KEY, slot=0x%X, id=%q", slotID, keyID)
	}

	if pubHandle != 0 {
		err = p11lib.Ctx.DestroyObject(session, pubHandle)
		if err != nil {
			return errors.WithStack(err)
		}
		logger.Infof("type=CKO_PUBLIC_KEY, slot=0x%X, id=%q", slotID, string(id))
	}
	return nil
}

// getPublicKeyPEM retrieves public key for the specified key
func (p11lib *PKCS11Lib) getPublicKeyPEM(slotID uint, keyID string) (string, error) {
	priv, err := p11lib.FindKeyPairOnSlot(slotID, keyID, "")
	if err != nil {
		return "", errors.WithMessagef(err, "reason=FindKeyPairOnSlot, slotID=%d, uriID=%s",
			slotID, keyID)
	}

	pub, err := ConvertToPublic(priv)
	if err != nil {
		return "", errors.WithStack(err)
	}

	pemKey, err := certutil.EncodePublicKeyToPEM(pub)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return string(pemKey), nil
}
