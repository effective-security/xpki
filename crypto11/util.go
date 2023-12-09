package crypto11

import (
	"strings"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// CurrentSlotID returns current slot ID
func (lib *PKCS11Lib) CurrentSlotID() uint {
	return lib.Slot.id
}

// TokensInfo returns list of tokens
func (lib *PKCS11Lib) TokensInfo() ([]*SlotTokenInfo, error) {
	list := []*SlotTokenInfo{}
	slots, err := lib.Ctx.GetSlotList(true)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	logger.KV(xlog.TRACE, "slots", len(slots))

	for _, slotID := range slots {
		si, err := lib.Ctx.GetSlotInfo(slotID)
		if err != nil {
			return nil, errors.WithMessagef(err, "GetSlotInfo: %d", slotID)
		}
		ti, err := lib.Ctx.GetTokenInfo(slotID)
		if err != nil {
			logger.KV(xlog.ERROR, "reason", "GetTokenInfo", "slotID", slotID, "ManufacturerID", si.ManufacturerID, "SlotDescription", si.SlotDescription, "err", err)
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
func (lib *PKCS11Lib) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	var err error
	session, err := lib.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return errors.WithMessagef(err, "OpenSession on slot %d", slotID)
	}
	defer func() {
		_ = lib.Ctx.CloseSession(session)
	}()

	var privHandle, pubHandle pkcs11.ObjectHandle
	if privHandle, err = lib.findKey(session, keyID, "", pkcs11.CKO_PRIVATE_KEY, ^uint(0)); err != nil {
		logger.KV(xlog.WARNING, "reason", "not_found", "type", "CKO_PRIVATE_KEY", "err", err.Error())
	}
	if pubHandle, err = lib.findKey(session, keyID, "", pkcs11.CKO_PUBLIC_KEY, ^uint(0)); err != nil {
		logger.KV(xlog.WARNING, "reason", "not_found", "type", "CKO_PUBLIC_KEY", "err", err.Error())
	}

	if privHandle != 0 {
		err = lib.Ctx.DestroyObject(session, privHandle)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	if pubHandle != 0 {
		err = lib.Ctx.DestroyObject(session, pubHandle)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// getPublicKeyPEM retrieves public key for the specified key
func (lib *PKCS11Lib) getPublicKeyPEM(slotID uint, keyID string) (string, error) {
	priv, err := lib.FindKeyPairOnSlot(slotID, keyID, "")
	if err != nil {
		return "", errors.WithMessagef(err, "unable to find key: slot=%d, key=%s", slotID, keyID)
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
