package cli

import (
	"context"
	"crypto"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"uuid"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
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
				Current:      true,
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{
			uint(1): {
				{
					ID:               "123",
					Label:            "label123",
					Type:             "RSA",
					Size:             2048,
					Usage:            cryptoprov.KeyUsageSign,
					State:            cryptoprov.KeyStateEnabled,
					Class:            "class",
					CurrentVersionID: "v124",
					CreationTime:     &creationTime,
					Tags:             map[string]string{"team": "alpha"},
					Meta: map[string]string{
						"usage": "u",
						"algo":  "a",
					},
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

	mocked.On("ListTokens").Times(2).Return(nil)
	mocked.On("ListKeys", "").Times(1).Return(nil)
	mocked.On("ListKeys", "with_error").Times(1).Return(errors.New("unexpected error"))
	mocked.On("ListTokens").Times(1).Return(errors.New("token not found"))
	mocked.On("Manufacturer").Return("man123")
	mocked.On("Model").Return("model123")

	c, _ = cryptoprov.New(mocked, nil)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText("Slot: 1\n  Manufacturer:  man123\n  Model:  model123\n  Description:  d123\n  Token serial:  serial123-30589673\n  Token label:  label123\n")
	s.HasText("[0]\n  Id:    123\n  Label:  label123\n  Type:  RSA\n  Size:  2048\n  Usage:  sign\n  State:  enabled\n  Class:  class\n  Version:  v124\n  Created: ")
	s.HasText("  Tag:  team=alpha\n  algo: a\n  usage: u\n[1]\n  Id:    with_error\n")
	// the listing asks for the PKI key types, the enabled and disabled
	// states, the metadata and the state, and never for a public key
	req := mocked.lastRequest
	s.Require().NotNil(req)
	s.Equal([]string{"RSA", "ECDSA", "ML-DSA"}, req.Filter.Types)
	s.Equal([]cryptoprov.KeyState{cryptoprov.KeyStateEnabled, cryptoprov.KeyStateDisabled}, req.Filter.States)
	s.Equal(cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState, req.Fields)
	s.Zero(req.Filter.Usage)

	cmd.Prefix = "with_error"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("failed to list keys on slot 1: unexpected error", err.Error())

	// no flags
	cmd = HsmLsKeyCmd{}
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("failed to list tokens: token not found", err.Error())

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

// TestLsKeyFilterFlags checks the listing each filter flag asks for.
func (s *hsmSuite) TestLsKeyFilterFlags() {
	for _, tc := range []struct {
		name string
		cmd  HsmLsKeyCmd
		req  cryptoprov.ListKeysRequest
		err  string
	}{
		{
			name: "defaults",
			req: cryptoprov.ListKeysRequest{
				PageSize: cryptoprov.MaxPageSize,
				Filter: cryptoprov.KeyFilter{
					Types:  defaultKeyTypes,
					States: defaultKeyStates,
				},
				Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
			},
		},
		{
			name: "every filter",
			cmd: HsmLsKeyCmd{
				Prefix: "ca-",
				Label:  "ca-2026",
				Usage:  "sign,encrypt",
				Type:   []string{"rsa,mldsa", "ecdsa"},
				Tag:    map[string]string{"team": "alpha"},
				State:  []string{"pending_deletion", "Destroyed"},
				Limit:  5,
			},
			req: cryptoprov.ListKeysRequest{
				PageSize: 5,
				Filter: cryptoprov.KeyFilter{
					LabelPrefix: "ca-",
					Label:       "ca-2026",
					Usage:       cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
					Types:       []string{"RSA", "ML-DSA", "ECDSA"},
					Tags:        map[string]string{"team": "alpha"},
					States:      []cryptoprov.KeyState{cryptoprov.KeyStatePendingDeletion, cryptoprov.KeyStateDestroyed},
				},
				Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
			},
		},
		{
			name: "every type and state",
			cmd: HsmLsKeyCmd{
				All:   true,
				State: []string{"all"},
			},
			req: cryptoprov.ListKeysRequest{
				PageSize: cryptoprov.MaxPageSize,
				Fields:   cryptoprov.KeyFieldMetadata,
			},
		},
		{
			name: "a limit above the largest page",
			cmd:  HsmLsKeyCmd{Limit: 5000},
			req: cryptoprov.ListKeysRequest{
				PageSize: cryptoprov.MaxPageSize,
				Filter: cryptoprov.KeyFilter{
					Types:  defaultKeyTypes,
					States: defaultKeyStates,
				},
				Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
			},
		},
		{
			name: "invalid usage",
			cmd:  HsmLsKeyCmd{Usage: "verify"},
			err:  `invalid key usage "verify": expected sign or encrypt`,
		},
		{
			name: "invalid type",
			cmd:  HsmLsKeyCmd{Type: []string{"DSA"}},
			err:  `unsupported key type: "DSA"`,
		},
		{
			name: "invalid state",
			cmd:  HsmLsKeyCmd{State: []string{"gone"}},
			err:  `invalid key state "gone": expected one of [enabled disabled pending_deletion destroyed unavailable]`,
		},
		{
			name: "invalid limit",
			cmd:  HsmLsKeyCmd{Limit: -1},
			err:  "invalid limit: -1",
		},
	} {
		s.Run(tc.name, func() {
			req, err := tc.cmd.request()
			if tc.err != "" {
				s.Require().EqualError(err, tc.err)
				return
			}
			s.Require().NoError(err)
			s.Equal(tc.req, *req)
		})
	}
}

// TestLsKeyPages checks that the listing reads every page, stops at --limit
// and reports an empty prefix listing, on the in-memory provider, which has
// no tokens.
func (s *hsmSuite) TestLsKeyPages() {
	prov := inmemcrypto.NewProvider()
	for i := range 5 {
		_, err := prov.GenerateKey(s.T().Context(), &cryptoprov.GenerateKeyRequest{
			Label: fmt.Sprintf("page-%d", i),
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Tags:  map[string]string{"n": strconv.Itoa(i)},
		})
		s.Require().NoError(err)
	}
	c, err := cryptoprov.New(prov, nil)
	s.Require().NoError(err)
	s.ctl.crypto = c
	s.ctl.defaultCryptoProv = c.Default()

	cmd := HsmLsKeyCmd{Prefix: "page-"}
	s.Require().NoError(cmd.Run(s.ctl))
	s.HasText("Slot: 0\n  Manufacturer:  inmem\n  Model:  inmem\n[0]\n", "[4]\n", "  Label:  page-4\n  Type:  ECDSA\n  Size:  256\n  Usage:  sign\n  State:  enabled\n", "  Tag:  n=4\n")
	s.HasNoText("[5]\n")

	s.Out.Reset()
	cmd.Limit = 2
	s.Require().NoError(cmd.Run(s.ctl))
	s.HasText("[1]\n")
	s.HasNoText("[2]\n")

	s.Out.Reset()
	cmd = HsmLsKeyCmd{Tag: map[string]string{"n": "3"}}
	s.Require().NoError(cmd.Run(s.ctl))
	s.HasText("[0]\n", "  Label:  page-3\n")
	s.HasNoText("[1]\n")

	s.Out.Reset()
	cmd = HsmLsKeyCmd{Prefix: "none-"}
	s.Require().NoError(cmd.Run(s.ctl))
	s.HasText("no keys found with prefix: none-\n")

	// a provider without tokens has no token to select
	s.Out.Reset()
	cmd = HsmLsKeyCmd{Token: "label123"}
	s.Require().NoError(cmd.Run(s.ctl))
	s.Empty(s.Out.String())
	info := HsmKeyInfoCmd{ID: "missing", Serial: "serial123"}
	s.Require().EqualError(info.Run(s.ctl), `token not found: serial="serial123", label=""`)

	// key info and removal through the provider itself
	var id string
	for key, err := range cryptoprov.AllKeys(s.T().Context(), prov, &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{Label: "page-0"},
	}) {
		s.Require().NoError(err)
		id = key.ID
	}
	s.Out.Reset()
	info = HsmKeyInfoCmd{ID: id, Public: true, Tags: true}
	s.Require().NoError(info.Run(s.ctl))
	s.HasText("  Id:    "+id+"\n", "  Label:  page-0\n", "  Tag:  n=0\n", "-----BEGIN PUBLIC KEY-----")
	rm := HsmRmKeyCmd{ID: id}
	s.Require().NoError(rm.Run(s.ctl))
	s.HasText("destroyed key: " + id)
	s.Require().ErrorIs(info.Run(s.ctl), cryptoprov.ErrKeyNotFound)
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
				Current:      true,
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

	mocked.On("ListTokens").Times(6).Return(nil)
	mocked.On("KeyInfo", "123", cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState|cryptoprov.KeyFieldPublicKey).Times(1).Return(nil)
	mocked.On("KeyInfo", "123", cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState).Return(nil)
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

	// filter by token label
	cmd.Token = "label123"
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText("Slot: 1", "Id:    123")

	// filter by serial
	cmd.Token = ""
	cmd.Serial = "serial123-30589673"
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	// no token matches the label
	cmd.Serial = ""
	cmd.Token = "unknown_label"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal(`token not found: serial="", label="unknown_label"`, err.Error())

	// no token matches the serial
	cmd.Token = ""
	cmd.Serial = "unknown_serial"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal(`token not found: serial="unknown_serial", label=""`, err.Error())

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
				Current:      true,
			},
		},
		keys: map[uint][]cryptoprov.KeyInfo{},
	}

	var pvk crypto.PrivateKey = struct{}{}
	mocked.On("GenerateKey", mock.Anything).Return(pvk, nil)
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
	cmd.Output = filepath.Join(s.tmpdir, uuid.NewV7().String())

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	cmd.Force = true
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("not exportable", err.Error())

	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal("key not found", err.Error())

	// the request of the provider: a signing RSA key with the label
	s.Require().NotNil(mocked.lastGenerate)
	s.Equal(cryptoprov.GenerateKeyRequest{
		Label: "label123",
		Type:  certutil.KeyTypeRSA,
		Size:  2048,
		Usage: cryptoprov.KeyUsageSign,
	}, *mocked.lastGenerate)

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
				Current:      true,
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

	mocked.On("ListTokens").Times(5).Return(nil)
	mocked.On("DestroyKey", "with_error").Return(errors.New("access denied"))
	mocked.On("DestroyKey", mock.Anything).Return(nil)
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

	// filter by token label
	cmd.Token = "label123"
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText("destroyed key: 123")

	// no token matches the label
	cmd.Token = "unknown_label"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal(`token not found: serial="", label="unknown_label"`, err.Error())

	// no token matches the serial
	cmd.Token = ""
	cmd.Serial = "unknown_serial"
	err = cmd.Run(s.ctl)
	s.Require().Error(err)
	s.Equal(`token not found: serial="unknown_serial", label=""`, err.Error())

	// assert that the expectations were met
	mocked.AssertExpectations(s.T())
}

// Mock
type mockedProvider struct {
	mock.Mock

	// lastGenerate is the request of the last GenerateKey call.
	lastGenerate *cryptoprov.GenerateKeyRequest
}

func (m *mockedProvider) GenerateKey(_ context.Context, req *cryptoprov.GenerateKeyRequest) (crypto.PrivateKey, error) {
	m.lastGenerate = req
	args := m.Called(req)
	return args.Get(0).(crypto.PrivateKey), args.Error(1)
}

func (m *mockedProvider) IdentifyKey(_ context.Context, k crypto.PrivateKey) (keyID, label string, err error) {
	args := m.Called(k)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *mockedProvider) ExportKey(_ context.Context, keyID string) (string, []byte, error) {
	args := m.Called(keyID)
	return args.String(0), args.Get(1).([]byte), args.Error(2)
}

func (m *mockedProvider) GetKey(_ context.Context, keyID string) (crypto.PrivateKey, error) {
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

// mockedFull is a provider with tokens: a cryptoprov.KeyManager and
// cryptoprov.TokenManager whose keys are those of its slots.
type mockedFull struct {
	mockedProvider

	tokens []cryptoprov.TokenInfo
	keys   map[uint][]cryptoprov.KeyInfo

	// lastRequest is the request of the last ListKeys call.
	lastRequest *cryptoprov.ListKeysRequest
}

func (m *mockedFull) ListTokens(context.Context) ([]cryptoprov.TokenInfo, error) {
	args := m.Called()
	err := args.Error(0)
	if err != nil {
		return nil, err
	}
	return m.tokens, nil
}

func (m *mockedFull) Token(uint) (cryptoprov.KeyManager, error) {
	return m, nil
}

// allKeys returns the keys of every slot, in slot order.
func (m *mockedFull) allKeys() []cryptoprov.KeyInfo {
	var keys []cryptoprov.KeyInfo
	for _, slot := range slices.Sorted(maps.Keys(m.keys)) {
		keys = append(keys, m.keys[slot]...)
	}
	return keys
}

func (m *mockedFull) ListKeys(_ context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	m.lastRequest = req
	args := m.Called(req.Filter.LabelPrefix)
	err := args.Error(0)
	if err != nil {
		return nil, err
	}
	return &cryptoprov.ListKeysResponse{Keys: m.allKeys()}, nil
}

func (m *mockedFull) DestroyKey(_ context.Context, keyID string) error {
	args := m.Called(keyID)
	return args.Error(0)
}

func (m *mockedFull) KeyInfo(_ context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	args := m.Called(keyID, fields)
	err := args.Error(0)
	if err != nil {
		return nil, err
	}

	for _, key := range m.allKeys() {
		if key.ID == keyID {
			return &key, nil
		}
	}
	return nil, args.Error(0)
}
