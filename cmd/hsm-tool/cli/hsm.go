package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"uuid"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/fileutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/x/print"
)

// HsmCmd is the parent for HSM command
type HsmCmd struct {
	List     HsmLsKeyCmd   `cmd:"" help:"list keys"`
	Info     HsmKeyInfoCmd `cmd:"" help:"print key information"`
	Generate HsmGenKeyCmd  `cmd:"" help:"generate key"`
	Remove   HsmRmKeyCmd   `cmd:"" help:"delete key"`
}

// HsmLsKeyCmd prints Keys
type HsmLsKeyCmd struct {
	Token  string `help:"specifies slot token (optional)"`
	Serial string `help:"specifies slot serial (optional)"`
	Prefix string `help:"specifies key label prefix (optional)"`
}

// tokenFilter selects tokens by serial or label for the HSM commands.
// An empty serial or label is not a filter value and never matches,
// so a token whose field happens to equal a sentinel can not be selected.
type tokenFilter struct {
	serial string
	label  string
	// isDefaultSlot is true when no filter was specified,
	// in which case only the default (current) slot is used.
	isDefaultSlot bool
}

func newTokenFilter(serial, label string) tokenFilter {
	return tokenFilter{
		serial:        serial,
		label:         label,
		isDefaultSlot: serial == "" && label == "",
	}
}

// matches returns true if the token is selected by the filter
func (f tokenFilter) matches(token cryptoprov.TokenInfo) bool {
	if f.isDefaultSlot {
		return true
	}
	return (f.serial != "" && token.Serial == f.serial) ||
		(f.label != "" && token.Label == f.label)
}

// errNotFound returns an error describing the filter that matched no token
func (f tokenFilter) errNotFound() error {
	return errors.Errorf("token not found: serial=%q, label=%q", f.serial, f.label)
}

// Run the command
func (a *HsmLsKeyCmd) Run(ctx *Cli) error {
	_, defprov := ctx.CryptoProv()
	keyProv, ok := defprov.(cryptoprov.KeyManager)
	if !ok {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	filter := newTokenFilter(a.Serial, a.Token)

	out := ctx.Writer()

	tokens, err := keyProv.EnumTokens(filter.isDefaultSlot)
	if err != nil {
		return errors.WithMessagef(err, "failed to list tokens")
	}

	printIfNotEmpty := func(label, val string) {
		if val != "" {
			_, _ = fmt.Fprintf(out, "%s:  %s\n", label, val)
		}
	}

	for _, token := range tokens {
		if filter.matches(token) {
			_, _ = fmt.Fprintf(out, "Slot: %d\n", token.SlotID)
			printIfNotEmpty("  Manufacturer", token.Manufacturer)
			printIfNotEmpty("  Model", token.Model)
			printIfNotEmpty("  Description", token.Description)
			printIfNotEmpty("  Token serial", token.Serial)
			printIfNotEmpty("  Token label", token.Label)

			keys, err := keyProv.EnumKeys(token.SlotID, a.Prefix)
			if err != nil {
				return errors.WithMessagef(err, "failed to list keys on slot %d", token.SlotID)
			}
			if a.Prefix != "" && len(keys) == 0 {
				_, _ = fmt.Fprintf(out, "no keys found with prefix: %s\n", a.Prefix)
			}
			for i, key := range keys {
				_, _ = fmt.Fprintf(out, "[%d]\n", i)
				_, _ = fmt.Fprintf(out, "  Id:    %s\n", key.ID)
				printIfNotEmpty("  Label", key.Label)
				printIfNotEmpty("  Type", key.Type)
				printIfNotEmpty("  Class", key.Class)
				printIfNotEmpty("  Version", key.CurrentVersionID)
				if key.CreationTime != nil {
					_, _ = fmt.Fprintf(out, "  Created: %s\n", key.CreationTime.Format(time.RFC3339))
				}
				for k, v := range key.Meta {
					_, _ = fmt.Fprintf(out, "  %s: %s\n", k, v)
				}
			}
		}
	}
	return nil
}

// HsmKeyInfoCmd prints the key info
type HsmKeyInfoCmd struct {
	ID     string `kong:"arg" required:"" help:"key ID"`
	Token  string `help:"slot token (optional)"`
	Serial string `help:"slot serial (optional)"`
	Public bool   `help:"print Public Key"`
}

// Run the command
func (a *HsmKeyInfoCmd) Run(ctx *Cli) error {
	_, defprov := ctx.CryptoProv()
	keyProv, ok := defprov.(cryptoprov.KeyManager)
	if !ok {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	filter := newTokenFilter(a.Serial, a.Token)

	out := ctx.Writer()

	tokens, err := keyProv.EnumTokens(filter.isDefaultSlot)
	if err != nil {
		return errors.WithMessagef(err, "failed to list tokens")
	}

	printIfNotEmpty := func(label, val string) {
		if val != "" {
			_, _ = fmt.Fprintf(out, "  %s:  %s\n", label, val)
		}
	}

	matched := false
	for _, token := range tokens {
		if filter.matches(token) {
			matched = true
			_, _ = fmt.Fprintf(out, "Slot: %d\n", token.SlotID)
			_, _ = fmt.Fprintf(out, "  Description:  %s\n", token.Description)
			_, _ = fmt.Fprintf(out, "  Token serial: %s\n", token.Serial)

			key, err := keyProv.KeyInfo(token.SlotID, a.ID, a.Public)
			if err != nil {
				return errors.WithMessagef(err, "failed to get key on slot %d", token.SlotID)
			}
			_, _ = fmt.Fprintf(out, "  Id:    %s\n", key.ID)
			printIfNotEmpty("  Label", key.Label)
			printIfNotEmpty("  Type", key.Type)
			printIfNotEmpty("  Class", key.Class)
			printIfNotEmpty("  Version", key.CurrentVersionID)
			if key.CreationTime != nil {
				_, _ = fmt.Fprintf(out, "  Created: %s\n", key.CreationTime.Format(time.RFC3339))
			}

			for k, v := range key.Meta {
				_, _ = fmt.Fprintf(out, "  %s: %s\n", k, v)
			}
			if key.PublicKey != "" {
				_, _ = fmt.Fprintf(out, "  Public key: \n%s\n", key.PublicKey)
			}
		}
	}
	if !matched {
		return filter.errNotFound()
	}

	return nil
}

// HsmGenKeyCmd generates key
type HsmGenKeyCmd struct {
	Algo    string `required:"" help:"algorithm: RSA|ECDSA"`
	Size    int    `required:"" help:"key size in bits"`
	Purpose string `required:"" help:"purpose of the key: SIGN|ENCRYPT"`
	Label   string `required:"" help:"name for generated key"`
	Output  string `help:"location to write the key, if not set, the output will be printed to STDOUT only"`
	Force   bool   `help:"force to override key file if exists"`
}

// Run the command
func (a *HsmGenKeyCmd) Run(ctx *Cli) error {
	if !a.Force && fileutil.FileExists(a.Output) == nil {
		return errors.Errorf("%q file exists, specify --force flag to override", a.Output)
	}

	_, crypto := ctx.CryptoProv()
	prov := csr.NewProvider(crypto)

	var purpose csr.KeyPurpose
	switch strings.ToLower(a.Purpose) {
	case "s", "sign", "signing":
		purpose = csr.SigningKey
	case "e", "encrypt", "encryption":
		purpose = csr.EncryptionKey
	default:
		return errors.Errorf("unsupported purpose: %q", a.Purpose)
	}

	req := prov.NewKeyRequest(prefixKeyLabel(a.Label), a.Algo, a.Size, purpose)
	prv, err := req.Generate()
	if err != nil {
		return err
	}

	keyID, _, err := crypto.IdentifyKey(prv)
	if err != nil {
		return err
	}

	uri, key, err := crypto.ExportKey(keyID)
	if err != nil {
		return err
	}

	if key == nil {
		key = []byte(uri)
	}

	if a.Output == "" {
		print.CertAndKey(ctx.Writer(), key, nil, nil)
	} else {
		err = os.WriteFile(a.Output, key, 0600)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// HsmRmKeyCmd deletes key
type HsmRmKeyCmd struct {
	ID     string `kong:"arg" required:"" help:"specifies key ID"`
	Token  string `help:"specifies slot token (optional)"`
	Serial string `help:"specifies slot serial (optional)"`
}

// Run the command
func (a *HsmRmKeyCmd) Run(ctx *Cli) error {
	_, defprov := ctx.CryptoProv()
	keyProv, ok := defprov.(cryptoprov.KeyManager)
	if !ok {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	filter := newTokenFilter(a.Serial, a.Token)

	tokens, err := keyProv.EnumTokens(filter.isDefaultSlot)
	if err != nil {
		return errors.WithMessagef(err, "failed to list tokens")
	}

	for _, token := range tokens {
		if filter.matches(token) {
			err := keyProv.DestroyKeyPairOnSlot(token.SlotID, a.ID)
			if err != nil {
				return errors.WithMessagef(err, "unable to destroy key %q on slot %d", a.ID, token.SlotID)
			}
			_, _ = fmt.Fprintf(ctx.Writer(), "destroyed key: %s\n", a.ID)
			return nil
		}
	}

	return filter.errNotFound()
}

// prefixKeyLabel adds a date prefix to label for a key
func prefixKeyLabel(label string) string {
	if strings.HasSuffix(label, "*") {
		g := uuid.NewV4().String()
		t := time.Now().UTC()
		label = strings.TrimSuffix(label, "*") +
			fmt.Sprintf("_%04d%02d%02d%02d%02d%02d_%x", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), g[:4])
	}

	return label
}
