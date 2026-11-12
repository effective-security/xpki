package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"uuid"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/fileutil"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/csr"
	"github.com/effective-security/xpki/v2/x/print"
)

// HsmCmd is the parent for HSM command
type HsmCmd struct {
	Key KeysCmd `cmd:"" help:"key management commands"`
}

// KeysCmd is the parent of the key commands, "hsm key list", "info",
// "generate" and "remove".
type KeysCmd struct {
	List     HsmLsKeyCmd   `cmd:"" help:"list keys"`
	Info     HsmKeyInfoCmd `cmd:"" help:"print key information"`
	Generate HsmGenKeyCmd  `cmd:"" help:"generate key"`
	Remove   HsmRmKeyCmd   `cmd:"" help:"delete key"`
}

// stateAll is the --state value that lists keys in every state, and
// listSeparator what separates the values of a list flag.
const (
	stateAll      = "all"
	listSeparator = ","
)

// defaultKeyTypes are the key types hsm key list shows without --type or --all:
// the asymmetric keys this module uses, not the symmetric data keys of a
// cloud account.
var defaultKeyTypes = []string{
	certutil.KeyTypeRSA,
	certutil.KeyTypeECDSA,
	certutil.KeyTypeMLDSA,
}

// defaultKeyStates are the key states hsm key list shows without --state.
var defaultKeyStates = []cryptoprov.KeyState{
	cryptoprov.KeyStateEnabled,
	cryptoprov.KeyStateDisabled,
}

// HsmLsKeyCmd prints Keys
type HsmLsKeyCmd struct {
	Token  string            `help:"specifies slot token (optional)"`
	Serial string            `help:"specifies slot serial (optional)"`
	Prefix string            `help:"specifies key label prefix (optional)"`
	Label  string            `help:"specifies the exact key label (optional)"`
	Usage  string            `help:"lists keys with one of the usages: sign,encrypt (optional)"`
	Type   []string          `help:"lists keys of the types: RSA,ECDSA,ML-DSA (default: all three)"`
	Tag    map[string]string `help:"lists keys with the tag or cloud label name=value; repeat the flag for several (not supported by PKCS#11)"`
	State  []string          `help:"lists keys in the states: enabled,disabled,pending_deletion,destroyed,unavailable, or all (default: enabled,disabled)"`
	Limit  int               `help:"lists at most this number of keys of a token (default: all)"`
	All    bool              `help:"lists keys of every type, including symmetric and MAC keys"`
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
		return token.Current
	}
	return (f.serial != "" && token.Serial == f.serial) ||
		(f.label != "" && token.Label == f.label)
}

// errNotFound returns an error describing the filter that matched no token
func (f tokenFilter) errNotFound() error {
	return errors.Errorf("token not found: serial=%q, label=%q", f.serial, f.label)
}

// selectedToken is a token the filter selected, with the manager of its
// keys.
type selectedToken struct {
	info cryptoprov.TokenInfo
	keys cryptoprov.KeyManager
}

// selectTokens returns the tokens of prov the filter selects. A provider
// with several tokens (cryptoprov.TokenManager, a PKCS#11 module) lists
// them; any other provider is one token without serial or label, which only
// the default filter selects.
func selectTokens(ctx context.Context, prov cryptoprov.Provider, filter tokenFilter) ([]selectedToken, error) {
	keyProv, ok := prov.(cryptoprov.KeyManager)
	if !ok {
		return nil, errors.Errorf("unsupported command for this crypto provider")
	}

	tokenProv, ok := prov.(cryptoprov.TokenManager)
	if !ok {
		token := cryptoprov.TokenInfo{
			Manufacturer: prov.Manufacturer(),
			Model:        prov.Model(),
			Current:      true,
		}
		if !filter.matches(token) {
			return nil, nil
		}
		return []selectedToken{
			{
				info: token,
				keys: keyProv,
			},
		}, nil
	}

	tokens, err := tokenProv.ListTokens(ctx)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to list tokens")
	}
	var selected []selectedToken
	for _, token := range tokens {
		if !filter.matches(token) {
			continue
		}
		keys := keyProv
		if !token.Current {
			if keys, err = tokenProv.Token(token.SlotID); err != nil {
				return nil, errors.WithMessagef(err, "failed to open token on slot %d", token.SlotID)
			}
		}
		selected = append(selected, selectedToken{
			info: token,
			keys: keys,
		})
	}
	return selected, nil
}

// splitList returns the values of a list flag, whose elements may be given
// separately or joined with commas, without empty ones.
func splitList(values []string) []string {
	var list []string
	for _, value := range values {
		for item := range strings.SplitSeq(value, listSeparator) {
			if item = strings.TrimSpace(item); item != "" {
				list = append(list, item)
			}
		}
	}
	return list
}

// keyType returns the cryptoprov key type a --type value names,
// case-insensitively and with "MLDSA" for ML-DSA.
func keyType(name string) (string, error) {
	upper := strings.ToUpper(name)
	if csr.IsPostQuantumAlgo(upper) {
		return certutil.KeyTypeMLDSA, nil
	}
	if slices.Contains(defaultKeyTypes, upper) {
		return upper, nil
	}
	return "", errors.Errorf("unsupported key type: %q", name)
}

// request returns the listing the flags describe: the keys of the PKI key
// types that are enabled or disabled, unless --type, --all or --state say
// otherwise.
func (a *HsmLsKeyCmd) request() (*cryptoprov.ListKeysRequest, error) {
	req := &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{
			Label:       a.Label,
			LabelPrefix: a.Prefix,
			Tags:        a.Tag,
			States:      defaultKeyStates,
		},
		Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
	}
	if a.Limit < 0 {
		return nil, errors.Errorf("invalid limit: %d", a.Limit)
	}
	// the largest page, so that a listing takes as few calls as possible
	req.PageSize = cryptoprov.MaxPageSize
	if a.Limit > 0 {
		req.PageSize = min(a.Limit, cryptoprov.MaxPageSize)
	}

	var err error
	if req.Filter.Usage, err = cryptoprov.ParseKeyUsage(a.Usage); err != nil {
		return nil, err
	}

	types := splitList(a.Type)
	switch {
	case len(types) > 0:
		for _, name := range types {
			t, err := keyType(name)
			if err != nil {
				return nil, err
			}
			req.Filter.Types = append(req.Filter.Types, t)
		}
	case !a.All:
		req.Filter.Types = defaultKeyTypes
	}

	if states := splitList(a.State); len(states) > 0 {
		req.Filter.States = nil
		for _, name := range states {
			if strings.EqualFold(name, stateAll) {
				// no state filter: the state is not read where it costs a
				// request per key
				req.Filter.States = nil
				req.Fields = cryptoprov.KeyFieldMetadata
				break
			}
			state, err := cryptoprov.ParseKeyState(name)
			if err != nil {
				return nil, err
			}
			req.Filter.States = append(req.Filter.States, state)
		}
	}
	return req, nil
}

// Run the command
func (a *HsmLsKeyCmd) Run(ctx *Cli) error {
	_, defprov, err := ctx.CryptoProv()
	if err != nil {
		return err
	}
	req, err := a.request()
	if err != nil {
		return err
	}
	tokens, err := selectTokens(ctx.Context(), defprov, newTokenFilter(a.Serial, a.Token))
	if err != nil {
		return err
	}

	out := ctx.Writer()
	for _, token := range tokens {
		_, _ = fmt.Fprintf(out, "Slot: %d\n", token.info.SlotID)
		printIfNotEmpty(out, "  Manufacturer", token.info.Manufacturer)
		printIfNotEmpty(out, "  Model", token.info.Model)
		printIfNotEmpty(out, "  Description", token.info.Description)
		printIfNotEmpty(out, "  Token serial", token.info.Serial)
		printIfNotEmpty(out, "  Token label", token.info.Label)

		count := 0
		for key, err := range cryptoprov.AllKeys(ctx.Context(), token.keys, req) {
			if err != nil {
				return errors.WithMessagef(err, "failed to list keys on slot %d", token.info.SlotID)
			}
			_, _ = fmt.Fprintf(out, "[%d]\n", count)
			printKey(out, key)
			count++
			if a.Limit > 0 && count == a.Limit {
				break
			}
		}
		if a.Prefix != "" && count == 0 {
			_, _ = fmt.Fprintf(out, "no keys found with prefix: %s\n", a.Prefix)
		}
	}
	return nil
}

// printIfNotEmpty prints "label:  val" unless val is empty.
func printIfNotEmpty(out io.Writer, label, val string) {
	if val != "" {
		_, _ = fmt.Fprintf(out, "%s:  %s\n", label, val)
	}
}

// printKey prints the fields of key that are set, then its tags and its
// provider details in name order.
func printKey(out io.Writer, key *cryptoprov.KeyInfo) {
	_, _ = fmt.Fprintf(out, "  Id:    %s\n", key.ID)
	printIfNotEmpty(out, "  Name", key.Name)
	printIfNotEmpty(out, "  Label", key.Label)
	printIfNotEmpty(out, "  Type", key.Type)
	if key.Size > 0 {
		_, _ = fmt.Fprintf(out, "  Size:  %d\n", key.Size)
	}
	printIfNotEmpty(out, "  Usage", key.Usage.String())
	printIfNotEmpty(out, "  State", string(key.State))
	printIfNotEmpty(out, "  Class", key.Class)
	printIfNotEmpty(out, "  Version", key.CurrentVersionID)
	if key.CreationTime != nil {
		_, _ = fmt.Fprintf(out, "  Created: %s\n", key.CreationTime.Format(time.RFC3339))
	}
	for _, name := range slices.Sorted(maps.Keys(key.Tags)) {
		_, _ = fmt.Fprintf(out, "  Tag:  %s=%s\n", name, key.Tags[name])
	}
	for _, name := range slices.Sorted(maps.Keys(key.Meta)) {
		_, _ = fmt.Fprintf(out, "  %s: %s\n", name, key.Meta[name])
	}
}

// HsmKeyInfoCmd prints the key info
type HsmKeyInfoCmd struct {
	ID     string `kong:"arg" required:"" help:"key ID"`
	Token  string `help:"slot token (optional)"`
	Serial string `help:"slot serial (optional)"`
	Public bool   `help:"print Public Key"`
	Tags   bool   `help:"print the tags or cloud labels of the key"`
}

// Run the command
func (a *HsmKeyInfoCmd) Run(ctx *Cli) error {
	_, defprov, err := ctx.CryptoProv()
	if err != nil {
		return err
	}
	filter := newTokenFilter(a.Serial, a.Token)
	tokens, err := selectTokens(ctx.Context(), defprov, filter)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return filter.errNotFound()
	}

	fields := cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState
	if a.Public {
		fields |= cryptoprov.KeyFieldPublicKey
	}
	if a.Tags {
		fields |= cryptoprov.KeyFieldTags
	}

	out := ctx.Writer()
	for _, token := range tokens {
		_, _ = fmt.Fprintf(out, "Slot: %d\n", token.info.SlotID)
		_, _ = fmt.Fprintf(out, "  Description:  %s\n", token.info.Description)
		_, _ = fmt.Fprintf(out, "  Token serial: %s\n", token.info.Serial)

		key, err := token.keys.KeyInfo(ctx.Context(), a.ID, fields)
		if err != nil {
			return errors.WithMessagef(err, "failed to get key on slot %d", token.info.SlotID)
		}
		printKey(out, key)
		if key.PublicKey != "" {
			_, _ = fmt.Fprintf(out, "  Public key: \n%s\n", key.PublicKey)
		}
	}

	return nil
}

// HsmGenKeyCmd generates key
type HsmGenKeyCmd struct {
	Algo    string `required:"" help:"algorithm: RSA|ECDSA|ML-DSA"`
	Size    int    `required:"" help:"key size in bits, or the ML-DSA parameter set: 44, 65 or 87"`
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

	_, crypto, err := ctx.CryptoProv()
	if err != nil {
		return err
	}
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
	prv, err := req.Generate(ctx.Context())
	if err != nil {
		return err
	}

	keyID, _, err := crypto.IdentifyKey(ctx.Context(), prv)
	if err != nil {
		return err
	}

	uri, key, err := crypto.ExportKey(ctx.Context(), keyID)
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
	_, defprov, err := ctx.CryptoProv()
	if err != nil {
		return err
	}
	filter := newTokenFilter(a.Serial, a.Token)
	tokens, err := selectTokens(ctx.Context(), defprov, filter)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return filter.errNotFound()
	}

	// the first selected token, as the key is destroyed once
	token := tokens[0]
	if err := token.keys.DestroyKey(ctx.Context(), a.ID); err != nil {
		return errors.WithMessagef(err, "unable to destroy key %q on slot %d", a.ID, token.info.SlotID)
	}
	_, _ = fmt.Fprintf(ctx.Writer(), "destroyed key: %s\n", a.ID)
	return nil
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
