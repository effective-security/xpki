package crypto11

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	pkcs11 "github.com/miekg/pkcs11"
	"gopkg.in/yaml.v3"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "crypto11")

// DefaultMaxSessions is the default limit of pooled sessions per slot
// of one PKCS11Lib; see WithMaxSessions.
const DefaultMaxSessions = 1024

// Option configures Init and ConfigureFromFile.
type Option func(*options)

type options struct {
	maxSessions int
}

// WithMaxSessions limits the pooled sessions that one PKCS11Lib keeps open
// on each slot (default DefaultMaxSessions). When all of them are in use,
// an operation waits until one is returned. The login session opened by
// Init is not counted. n must be positive.
func WithMaxSessions(n int) Option {
	return func(o *options) {
		o.maxSessions = n
	}
}

// TokenConfig holds PKCS#11 configuration information.
//
// Init selects the token by the configured serial number and label:
// empty fields are ignored, so a token must match every nonempty one, and
// at least one of them is required. If several tokens match, the first
// slot wins.
//
// Supply this to Init, or alternatively use ConfigureFromFile.
type TokenConfig interface {
	// Manufacturer name of the manufacturer
	Manufacturer() string

	// Model name of the device
	Model() string

	// Full path to PKCS#11 library
	Path() string

	// Token serial number; empty matches any serial
	TokenSerial() string

	// Token label; empty matches any label
	TokenLabel() string

	// Pin is a secret to access the token.
	// If it's prefixed with `file:`, then it will be loaded from the file.
	Pin() string

	// Comma separated key=value pair of attributes(e.g. "ServiceName=x,UserName=y")
	Attributes() string
}

type config struct {
	Man    string `json:"Manufacturer" yaml:"manufacturer"`
	Mod    string `json:"Model"        yaml:"model"`
	Dir    string `json:"Path"         yaml:"path"`
	Serial string `json:"TokenSerial"  yaml:"token_serial"`
	Label  string `json:"TokenLabel"   yaml:"token_label"`
	Pwd    string `json:"Pin"          yaml:"pin"`
	Attrs  string `json:"Attributes"   yaml:"attributes"`
}

// Manufacturer name of the manufacturer
func (c *config) Manufacturer() string {
	return c.Man
}

// Model name of the device
func (c *config) Model() string {
	return c.Mod
}

// Full path to PKCS#11 library
func (c *config) Path() string {
	return c.Dir
}

// Token serial number
func (c *config) TokenSerial() string {
	return c.Serial
}

// Token label
func (c *config) TokenLabel() string {
	return c.Label
}

// Pin is a secret to access the token.
// If it's prefixed with `file:`, then it will be loaded from the file.
func (c *config) Pin() string {
	return c.Pwd
}

// Comma separated key=value pair of attributes(e.g. "ServiceName=x,UserName=y")
func (c *config) Attributes() string {
	return c.Attrs
}

// Init configures PKCS#11 from a TokenConfig, opens the token slot and
// logs in when the token requires it.
//
// The library at config.Path() is loaded and initialized by the first
// PKCS11Lib that uses it and shared by later ones. On error Init releases
// everything it acquired. Call Close to release the returned PKCS11Lib.
func Init(config TokenConfig, opts ...Option) (_ *PKCS11Lib, err error) {
	o := options{
		maxSessions: DefaultMaxSessions,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("crypto11: nil option")
		}
		opt(&o)
	}
	if o.maxSessions < 1 {
		return nil, errors.Errorf("crypto11: invalid max sessions: %d", o.maxSessions)
	}
	serial, label := config.TokenSerial(), config.TokenLabel()
	if serial == "" && label == "" {
		return nil, errors.WithStack(errNoTokenSelector)
	}

	mod, err := openModule(config.Path())
	if err != nil {
		return nil, err
	}
	lib := newPKCS11Lib(config, mod.ctx, o.maxSessions, ctxSessionOps(mod.ctx))
	lib.module = mod
	defer func() {
		if err != nil {
			if cerr := lib.Close(); cerr != nil {
				err = errors.Join(err, errors.WithMessage(cerr, "release after failed init"))
			}
		}
	}()

	slots, err := lib.TokensInfo()
	if err != nil {
		return nil, errors.WithMessage(err, "TokensInfo failed")
	}

	if lib.Slot, err = selectToken(slots, serial, label); err != nil {
		return nil, err
	}

	if lib.Session, err = lib.NewSession(lib.Slot.id); err != nil {
		return nil, errors.WithMessage(err, "open PKCS#11 session")
	}
	if lib.Slot.flags&pkcs11.CKF_LOGIN_REQUIRED != 0 {
		err = lib.Ctx.Login(lib.Session, pkcs11.CKU_USER, config.Pin())
		if err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
			return nil, errors.WithMessage(err, "login into PKCS#11 token")
		}
	}
	return lib, nil
}

// selectToken returns the first token that matches every nonempty selector
// (XPKI-006). It returns errNoTokenSelector when both are empty and
// errTokenNotFound when no token matches.
func selectToken(slots []*SlotTokenInfo, serial, label string) (*SlotTokenInfo, error) {
	if serial == "" && label == "" {
		return nil, errors.WithStack(errNoTokenSelector)
	}
	for _, slot := range slots {
		logger.KV(xlog.TRACE, "state", "search", "slot", slot.id, "serial", slot.serial, "label", slot.label)
		if (serial == "" || slot.serial == serial) && (label == "" || slot.label == label) {
			logger.KV(xlog.TRACE, "state", "found", "slot", slot.id, "serial", slot.serial, "label", slot.label)
			return slot, nil
		}
	}
	return nil, errors.WithStack(errTokenNotFound)
}

func newPKCS11Lib(config TokenConfig, ctx *pkcs11.Ctx, maxSessions int, ops sessionOps) *PKCS11Lib {
	lib := &PKCS11Lib{
		Ctx:         ctx,
		Config:      config,
		maxSessions: maxSessions,
		ops:         ops,
		pools:       map[uint]*sessionPool{},
	}
	lib.drained.L = &lib.mu
	return lib
}

// ConfigureFromFile loads a token configuration with LoadTokenConfig and
// opens it with Init; opts and the returned PKCS11Lib are as for Init.
func ConfigureFromFile(configLocation string, opts ...Option) (*PKCS11Lib, error) {
	cfg, err := LoadTokenConfig(configLocation)
	if err != nil {
		return nil, errors.WithMessagef(err, "load p11 config: %q", configLocation)
	}
	lib, err := Init(cfg, opts...)
	if err != nil {
		return nil, errors.WithMessagef(err, "initialize p11 config: %q", configLocation)
	}
	return lib, nil
}

// LoadTokenConfig loads PKCS#11 token configuration
func LoadTokenConfig(filename string) (TokenConfig, error) {
	cfr, err := os.Open(filename)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() {
		_ = cfr.Close()
	}()
	tokenConfig := new(config)

	if strings.HasSuffix(filename, ".json") {
		err = json.NewDecoder(cfr).Decode(tokenConfig)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		err = yaml.NewDecoder(cfr).Decode(tokenConfig)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	pin := tokenConfig.Pin()
	if strings.HasPrefix(pin, "file:") {
		pb, err := os.ReadFile(strings.TrimPrefix(pin, "file:"))
		if err != nil {
			return nil, errors.WithStack(err)
		}
		// only line endings are stripped so a PIN containing spaces is kept intact
		tokenConfig.Pwd = strings.TrimRight(string(pb), "\r\n")
	}

	return tokenConfig, nil
}
