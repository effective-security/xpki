package cli

import (
	"crypto"
	"crypto/elliptic"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/x/guid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type hsmSuite struct {
	testSuite
}

func TestHsmSuite(t *testing.T) {
	suite.Run(t, new(hsmSuite))
}

func (s *hsmSuite) TestLsKeyFlags() {
	cmd := HsmLsKeyCmd{}

	// without KeyManager interface
	mockedProv := &mockedProvider{}
	mockedProv.On("Manufacturer").Return("man123")
	mockedProv.On("Model").Return("model123")

	c, _ := cryptoprov.New(mockedProv, nil)

	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err := cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("unsupported command for this crypto provider", err.Error())

	// with keys and creationTime
	creationTime := time.Now()
	mocked := &mockedFull{
		tokens: []cryptoprov.TokenInfo{
			{
				SlotID:       uint(1),
				Description:  "d123",
				Label:        "label123",
				Manufacturer: "man123",
				Model:        "model123",
				Serial:       "serial123-30589673",
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{
			uint(1): {
				{
					ID:               "123",
					Label:            "label123",
					Type:             "RSA",
					Class:            "class",
					CurrentVersionID: "v124",
					CreationTime:     &creationTime,
				},
				{
					ID:               "with_error",
					Label:            "with_error",
					Type:             "ECDSA",
					Class:            "class",
					CurrentVersionID: "v1235",
					CreationTime:     &creationTime,
				},
			},
		},
	}

	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(2).Return(nil)
	mocked.On("EnumKeys", mock.Anything, mock.Anything, mock.Anything).Times(1).Return(nil)
	mocked.On("EnumKeys", mock.Anything, "with_error", mock.Anything).Times(1).Return(errors.New("unexpected error"))
	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(1).Return(errors.New("token not found"))
	mocked.On("Manufacturer").Return("man123")
	mocked.On("Model").Return("model123")

	c, _ = cryptoprov.New(mocked, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText("Slot: 1\n  Manufacturer:  man123\n  Model:  model123\n  Description:  d123\n  Token serial:  serial123-30589673\n  Token label:  label123\n")
	s.HasText("Created: ")

	cmd.Prefix = "with_error"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("failed to list keys on slot 1: unexpected error", err.Error())

	// no flags
	cmd = HsmLsKeyCmd{}
	err = cmd.Run(s.ctl)
	s.Require().Error(err)

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

func (s *hsmSuite) Test_KeyInfo() {
	cmd := HsmKeyInfoCmd{
		ID:     "123",
		Public: true,
	}

	// without KeyManager interface
	mockedProv := &mockedProvider{}
	mockedProv.On("Manufacturer").Return("man123")
	mockedProv.On("Model").Return("model123")

	c, _ := cryptoprov.New(mockedProv, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err := cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("unsupported command for this crypto provider", err.Error())

	// with keys and creationTime
	creationTime := time.Now()
	mocked := &mockedFull{
		tokens: []cryptoprov.TokenInfo{
			{
				SlotID:       uint(1),
				Description:  "d123",
				Label:        "label123",
				Manufacturer: "man123",
				Model:        "model123",
				Serial:       "serial123-30589673",
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{
			uint(1): {
				{
					ID:               "123",
					Label:            "label123",
					Type:             "RSA",
					Class:            "class",
					CurrentVersionID: "v124",
					CreationTime:     &creationTime,
				},
			},
		},
	}

	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(2).Return(nil)
	//mocked.On("EnumKeys", mock.Anything, mock.Anything, mock.Anything).Times(1).Return(nil)
	mocked.On("KeyInfo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mocked.On("Manufacturer").Return("man123")
	mocked.On("Model").Return("model123")

	c, _ = cryptoprov.New(mocked, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	// no flags
	cmd.Public = false
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

func (s *hsmSuite) Test_GenKey() {
	cmd := HsmGenKeyCmd{
		Algo:    "RSA",
		Size:    1024,
		Purpose: "sign",
		Label:   "label123",
		Output:  "",
		Force:   false,
	}

	mocked := &mockedFull{
		tokens: []cryptoprov.TokenInfo{
			{
				SlotID:       uint(1),
				Description:  "d123",
				Label:        "label123",
				Manufacturer: "man123",
				Model:        "model123",
				Serial:       "serial123-30589673",
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{},
	}

	var pvk crypto.PrivateKey = struct{}{}
	mocked.On("GenerateRSAKey", mock.Anything, mock.Anything, mock.Anything).Return(pvk, nil)
	mocked.On("IdentifyKey", mock.Anything).Times(2).Return("keyID123", "label123", nil)
	mocked.On("ExportKey", "keyID123").Times(1).Return("pkcs11:keyID123", []byte{1, 2, 3}, nil)
	mocked.On("ExportKey", "keyID123").Times(1).Return("", []byte{}, errors.Errorf("not exportable"))
	mocked.On("IdentifyKey", mock.Anything).Times(1).Return("", "", errors.Errorf("key not found"))
	mocked.On("Manufacturer").Return("man123")
	mocked.On("Model").Return("model123")

	c, _ := cryptoprov.New(mocked, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err := cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("validate RSA key: RSA key is too weak: 1024", err.Error())

	cmd.Size = 2048
	cmd.Output = filepath.Join(s.tmpdir, guid.MustCreate())

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	cmd.Force = true
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("not exportable", err.Error())

	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("key not found", err.Error())

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

func (s *hsmSuite) Test_RmKey() {
	cmd := HsmRmKeyCmd{}

	// without KeyManager interface
	mockedProv := &mockedProvider{}
	mockedProv.On("Manufacturer").Return("man123")
	mockedProv.On("Model").Return("model123")

	c, _ := cryptoprov.New(mockedProv, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err := cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("unsupported command for this crypto provider", err.Error())

	// with keys and creationTime
	creationTime := time.Now()
	mocked := &mockedFull{
		tokens: []cryptoprov.TokenInfo{
			{
				SlotID:       uint(1),
				Description:  "d123",
				Label:        "label123",
				Manufacturer: "man123",
				Model:        "model123",
				Serial:       "serial123-30589673",
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{
			uint(1): {
				{
					ID:               "123",
					Label:            "label123",
					Type:             "RSA",
					Class:            "class",
					CurrentVersionID: "v124",
					CreationTime:     &creationTime,
				},
				{
					ID:               "with_error",
					Label:            "with_error",
					Type:             "ECDSA",
					Class:            "class",
					CurrentVersionID: "v1235",
					CreationTime:     &creationTime,
				},
			},
		},
	}

	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(2).Return(nil)
	mocked.On("DestroyKeyPairOnSlot", mock.Anything, "with_error").Return(errors.New("access denied"))
	mocked.On("DestroyKeyPairOnSlot", mock.Anything, mock.Anything).Return(nil)
	mocked.On("Manufacturer").Return("man123")
	mocked.On("Model").Return("model123")

	c, _ = cryptoprov.New(mocked, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	cmd.ID = "with_error"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal(`unable to destroy key "with_error" on slot 1: access denied`, err.Error())

	cmd.ID = "123"
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

//
// Mock
//
type mockedProvider struct {
	mock.Mock
}

func (m *mockedProvider) GenerateRSAKey(label string, bits int, purpose int) (crypto.PrivateKey, error) {
	args := m.Called(label, bits, purpose)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedProvider) GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error) {
	args := m.Called(label, curve)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedProvider) IdentifyKey(k crypto.PrivateKey) (keyID, label string, err error) {
	args := m.Called(k)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *mockedProvider) ExportKey(keyID string) (string, []byte, error) {
	args := m.Called(keyID)
	return args.String(0), args.Get(1).([]byte), args.Error(2)
}

func (m *mockedProvider) GetKey(keyID string) (crypto.PrivateKey, error) {
	args := m.Called(keyID)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedProvider) Manufacturer() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockedProvider) Model() string {
	args := m.Called()
	return args.String(0)
}

type mockedFull struct {
	mockedProvider

	tokens []cryptoprov.TokenInfo
	keys   map[uint][]cryptoprov.KeyInfo
}

func (m *mockedFull) CurrentSlotID() uint {
	args := m.Called()
	return uint(args.Int(0))
}

func (m *mockedFull) EnumTokens(currentSlotOnly bool) ([]cryptoprov.TokenInfo, error) {
	args := m.Called(currentSlotOnly)
	err := args.Error(0)
	if err != nil {
		return nil, err
	}
	return m.tokens, nil
}

func (m *mockedFull) EnumKeys(slotID uint, prefix string) ([]cryptoprov.KeyInfo, error) {
	args := m.Called(slotID, prefix)
	err := args.Error(0)
	if err != nil {
		return nil, err
	}
	return m.keys[slotID], err
}

func (m *mockedFull) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	args := m.Called(slotID, keyID)
	return args.Error(0)
}

func (m *mockedFull) FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error) {
	args := m.Called(slotID, keyID, label)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedFull) KeyInfo(slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	args := m.Called(slotID, keyID, includePublic)
	err := args.Error(0)
	if err != nil {
		return nil, err
	}

	for _, key := range m.keys[slotID] {
		if key.ID == keyID {
			return &key, nil
		}
	}
	return nil, args.Error(0)
}
