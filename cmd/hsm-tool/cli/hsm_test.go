package cli

import (
	"crypto"
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func Test_CliSuite(t *testing.T) {
	suite.Run(t, new(testSuite))
}

func (s *testSuite) TestLsKeyFlags() {
	cmd := HsmLsKeyCmd{}

	// without KeyManager interface
	c, _ := cryptoprov.New(&mockedProvider{}, nil)
	s.ctl.crypto = c

	err := cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("unsupported command for this crypto provider", err.Error())

	// with keys and creationTime
	creationTime := time.Now()
	mocked := &mockedFull{
		tokens: []slot{
			{
				slotID:       uint(1),
				description:  "d123",
				label:        "label123",
				manufacturer: "man123",
				model:        "model123",
				serial:       "serial123-30589673",
			},
		},
		keys: map[uint][]keyInfo{
			uint(1): {
				{
					id:               "123",
					label:            "label123",
					typ:              "RSA",
					class:            "class",
					currentVersionID: "v124",
					creationTime:     &creationTime,
				},
				{
					id:               "with_error",
					label:            "with_error",
					typ:              "ECDSA",
					class:            "class",
					currentVersionID: "v1235",
					creationTime:     &creationTime,
				},
			},
		},
	}
	c, _ = cryptoprov.New(mocked, nil)
	s.ctl.crypto = c

	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(2).Return(nil)
	mocked.On("EnumKeys", mock.Anything, mock.Anything, mock.Anything).Times(1).Return(nil)
	mocked.On("EnumKeys", mock.Anything, "with_error", mock.Anything).Times(1).Return(errors.New("unexpected error"))
	mocked.On("EnumTokens", mock.Anything, mock.Anything).Times(1).Return(errors.New("token not found"))

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText("Slot: 1\n  Description:  d123\n  Token serial: serial123-30589673\n  Token label:  label123\n")
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

type slot struct {
	slotID       uint
	description  string
	label        string
	manufacturer string
	model        string
	serial       string
}

type keyInfo struct {
	id               string
	label            string
	typ              string
	class            string
	currentVersionID string
	creationTime     *time.Time
}
type mockedFull struct {
	mockedProvider

	tokens []slot
	keys   map[uint][]keyInfo
}

func (m *mockedFull) CurrentSlotID() uint {
	args := m.Called()
	return uint(args.Int(0))
}

func (m *mockedFull) EnumTokens(currentSlotOnly bool, slotInfoFunc func(slotID uint, description, label, manufacturer, model, serial string) error) error {
	args := m.Called(currentSlotOnly, slotInfoFunc)
	err := args.Error(0)
	if err == nil {
		for _, token := range m.tokens {
			err = slotInfoFunc(token.slotID, token.description, token.label, token.manufacturer, token.model, token.serial)
			if err != nil {
				return err
			}
		}
	}
	return err
}

func (m *mockedFull) EnumKeys(slotID uint, prefix string, keyInfoFunc func(id, label, typ, class, currentVersionID string, creationTime *time.Time) error) error {
	args := m.Called(slotID, prefix, keyInfoFunc)
	err := args.Error(0)
	if err == nil {
		for _, key := range m.keys[slotID] {
			if prefix == "" || strings.HasPrefix(key.label, prefix) {
				err = keyInfoFunc(key.id, key.label, key.typ, key.class, key.currentVersionID, key.creationTime)
				if err != nil {
					return err
				}
			}
		}
	}
	return err
}

func (m *mockedFull) DestroyKeyPairOnSlot(slotID uint, keyID string) error {
	args := m.Called(slotID, keyID)
	return args.Error(0)
}

func (m *mockedFull) FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error) {
	args := m.Called(slotID, keyID, label)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedFull) KeyInfo(slotID uint, keyID string, includePublic bool, keyInfoFunc func(id, label, typ, class, currentVersionID, pubKey string, creationTime *time.Time) error) error {
	args := m.Called(slotID, keyID, includePublic, keyInfoFunc)
	return args.Error(0)
}
