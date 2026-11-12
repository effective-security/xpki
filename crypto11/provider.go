package crypto11

import (
	"context"
	"math/big"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/miekg/pkcs11"
)

// metaKeyType is the KeyInfo.Meta entry with the PKCS#11 key type name of a
// key whose family cryptoprov has no type for, such as DSA.
const metaKeyType = "key_type"

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
var _ cryptoprov.TokenManager = (*PKCS11Lib)(nil)

// keyTypes maps the cryptoprov key types to their CKA_KEY_TYPE.
var keyTypes = map[string]uint{
	certutil.KeyTypeRSA:   pkcs11.CKK_RSA,
	certutil.KeyTypeECDSA: pkcs11.CKK_EC,
	certutil.KeyTypeMLDSA: ckkMLDSA,
}

// mldsaSizes maps the CKA_PARAMETER_SET values to the parameter set number
// of KeyInfo.Size.
var mldsaSizes = map[uint]int{
	ckpMLDSA44: cryptoprov.MLDSA44,
	ckpMLDSA65: cryptoprov.MLDSA65,
	ckpMLDSA87: cryptoprov.MLDSA87,
}

// optionalAttributeErrors are the results of C_GetAttributeValue for an
// attribute the object does not have or does not reveal. The key details
// they would supply are left out instead of failing the call.
var optionalAttributeErrors = []pkcs11.Error{
	pkcs11.CKR_ATTRIBUTE_TYPE_INVALID,
	pkcs11.CKR_ATTRIBUTE_SENSITIVE,
}

// ListTokens returns the tokens of the PKCS#11 module that have a serial
// number or a label; Current marks the one lib is logged in to.
func (lib *PKCS11Lib) ListTokens(ctx context.Context) ([]cryptoprov.TokenInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	list, err := lib.TokensInfo()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	res := make([]cryptoprov.TokenInfo, len(list))
	for i, ti := range list {
		res[i] = cryptoprov.TokenInfo{
			SlotID:       ti.id,
			Description:  ti.description,
			Label:        ti.label,
			Manufacturer: ti.manufacturer,
			Model:        ti.model,
			Serial:       ti.serial,
			Current:      ti.id == lib.Slot.id,
		}
	}
	return res, nil
}

// Token returns the KeyManager of the token in slot slotID. Only the token
// lib is logged in to shows its private keys and is logged in again after a
// logout (XPKI-110); on another slot the manager sees what the token gives
// a public session. It fails after Close.
func (lib *PKCS11Lib) Token(slotID uint) (cryptoprov.KeyManager, error) {
	if err := lib.enter(); err != nil {
		return nil, err
	}
	lib.exit()
	return &tokenKeyManager{
		lib:  lib,
		slot: slotID,
	}, nil
}

// tokenKeyManager is the cryptoprov.KeyManager of one slot of lib.
type tokenKeyManager struct {
	lib  *PKCS11Lib
	slot uint
}

func (m *tokenKeyManager) ListKeys(ctx context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	return m.lib.listKeysOnSlot(ctx, m.slot, req)
}

func (m *tokenKeyManager) KeyInfo(ctx context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	return m.lib.keyInfoOnSlot(ctx, m.slot, keyID, fields)
}

func (m *tokenKeyManager) DestroyKey(ctx context.Context, keyID string) error {
	return m.lib.destroyKeyOnSlot(ctx, m.slot, keyID)
}

// ListKeys returns one page of the private keys of the token lib is logged
// in to.
//
// The filter becomes the C_FindObjectsInit template where it can: the
// private key class, CKA_KEY_TYPE for one type, CKA_LABEL for the exact
// label, and CKA_SIGN or, for RSA keys, CKA_DECRYPT for one usage. A label
// prefix, several types and a usage of either kind are checked on the
// attributes of each candidate, at most a page of candidates per call. The
// usage is what the token says: CKA_SIGN, and CKA_DECRYPT of an RSA key. A
// key GenerateKey created has only the usage it was asked for; a key
// created without one of the attributes has the token's default, which is
// true for both on SoftHSM. A PKCS#11 object has no
// tags, so a filter on tags is a wrapped cryptoprov.ErrNotSupported, and it
// has no state: every key is enabled.
//
// The page token is the offset in the search order of the token, so a key
// created or destroyed between two pages can be repeated or missed.
// Attributes are read for the keys of the page only: ID, label, type and
// class always, and usage and size with cryptoprov.KeyFieldMetadata. ctx is
// checked between the batches of the search and between keys; a PKCS#11
// call that has started is not interrupted.
//
// It uses its own read-only session rather than a pooled RW one, so a
// write-protected token can still be listed. Private keys are visible only
// to a logged-in session, and a logged-out token lists none without an
// error, so the session state is checked first and the token is logged in
// again when needed (XPKI-110).
func (lib *PKCS11Lib) ListKeys(ctx context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	return lib.listKeysOnSlot(ctx, lib.Slot.id, req)
}

// KeyInfo describes the private key with CKA_ID keyID on the token lib is
// logged in to: every field of the Metadata and State groups and, with
// cryptoprov.KeyFieldPublicKey, the PEM public key of its pair. A key the
// token does not have is a wrapped cryptoprov.ErrKeyNotFound. ctx bounds
// the wait for a session.
func (lib *PKCS11Lib) KeyInfo(ctx context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	return lib.keyInfoOnSlot(ctx, lib.Slot.id, keyID, fields)
}

// DestroyKey destroys the private and the public key objects with CKA_ID
// keyID on the token lib is logged in to. One missing half is tolerated; a
// key with neither is a wrapped cryptoprov.ErrKeyNotFound. ctx bounds the
// wait for a session.
func (lib *PKCS11Lib) DestroyKey(ctx context.Context, keyID string) error {
	return lib.destroyKeyOnSlot(ctx, lib.Slot.id, keyID)
}

// keySearch is a key filter as a PKCS#11 search: the template the token
// evaluates and the conditions left to check on each candidate.
type keySearch struct {
	template []*pkcs11.Attribute

	labelPrefix string
	// types is set when the filter names several types
	types []string
	// usage is set when the filter accepts either usage
	usage cryptoprov.KeyUsage
}

// newKeySearch returns the search for f, or false when no key of a token can
// pass it: a type PKCS#11 does not have, or states without enabled.
func newKeySearch(f *cryptoprov.KeyFilter) (*keySearch, bool) {
	if len(f.States) > 0 && !slices.Contains(f.States, cryptoprov.KeyStateEnabled) {
		return nil, false
	}
	s := &keySearch{
		template: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		},
		labelPrefix: f.LabelPrefix,
	}

	types := slices.Compact(slices.Sorted(slices.Values(f.Types)))
	switch len(types) {
	case 0:
	case 1:
		keyType, ok := keyTypes[types[0]]
		if !ok {
			return nil, false
		}
		s.template = append(s.template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType))
	default:
		s.types = types
	}
	if f.Label != "" {
		s.template = append(s.template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(f.Label)))
	}
	switch f.Usage {
	case 0:
	case cryptoprov.KeyUsageSign:
		s.template = append(s.template, pkcs11.NewAttribute(pkcs11.CKA_SIGN, true))
	case cryptoprov.KeyUsageEncrypt:
		// only an RSA key decrypts, whatever a token sets CKA_DECRYPT to
		// on the others
		if len(types) > 0 && !slices.Contains(types, certutil.KeyTypeRSA) {
			return nil, false
		}
		if len(types) != 1 {
			s.types = nil
			s.template = append(s.template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA))
		}
		s.template = append(s.template, pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
	default:
		s.usage = f.Usage
	}
	return s, true
}

// filtersCandidates reports whether a condition is left to check on the
// attributes of each candidate.
func (s *keySearch) filtersCandidates() bool {
	return s.labelPrefix != "" || len(s.types) > 0 || s.usage != 0
}

// match reports whether key passes the conditions the template does not
// have.
func (s *keySearch) match(key *cryptoprov.KeyInfo) bool {
	if !strings.HasPrefix(key.Label, s.labelPrefix) {
		return false
	}
	if len(s.types) > 0 && !slices.Contains(s.types, key.Type) {
		return false
	}
	return s.usage == 0 || key.Usage&s.usage != 0
}

func (lib *PKCS11Lib) listKeysOnSlot(ctx context.Context, slotID uint, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if len(req.Filter.Tags) > 0 {
		return nil, errors.Wrap(cryptoprov.ErrNotSupported, "a PKCS#11 key has no tags to filter on")
	}
	cursor, err := cryptoprov.ParsePageToken(req)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	search, ok := newKeySearch(&req.Filter)
	if !ok {
		return &cryptoprov.ListKeysResponse{Keys: []cryptoprov.KeyInfo{}}, nil
	}

	if err := lib.enter(); err != nil {
		return nil, err
	}
	defer lib.exit()

	gen := lib.loginGen.Load()
	sh, err := lib.Ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, errors.WithMessagef(err, "OpenSession on slot %d", slotID)
	}
	defer func() {
		_ = lib.Ctx.CloseSession(sh)
	}()
	if lib.loginRequired() && slotID == lib.Slot.id {
		state, err := lib.ops.state(sh)
		if err != nil {
			return nil, errors.WithMessagef(err, "GetSessionInfo on slot %d", slotID)
		}
		if state == pkcs11.CKS_RO_PUBLIC_SESSION {
			if err := lib.relogin(gen); err != nil {
				return nil, errors.WithMessage(err, "re-login for a logged-out token")
			}
		}
	}
	return lib.listKeysOnSession(ctx, sh, req, search, cursor.Offset)
}

// listKeysOnSession returns the page of the search that starts at offset in
// the search order.
func (lib *PKCS11Lib) listKeysOnSession(ctx context.Context, sh pkcs11.SessionHandle, req *cryptoprov.ListKeysRequest, search *keySearch, offset int) (*cryptoprov.ListKeysResponse, error) {
	limit := req.Limit(cryptoprov.DefaultPageSize)
	// with conditions to check on each candidate, a call examines a batch
	// of them and may return a short page
	window := limit
	if search.filtersCandidates() {
		window = max(limit, findObjectsBatchSize)
	}
	handles, more, err := lib.findObjectsWindow(ctx, sh, search.template, offset, window)
	if err != nil {
		return nil, err
	}

	details := req.Fields.Has(cryptoprov.KeyFieldMetadata) || search.usage != 0
	res := &cryptoprov.ListKeysResponse{
		Keys: make([]cryptoprov.KeyInfo, 0, min(limit, len(handles))),
	}
	examined := 0
	for _, handle := range handles {
		if len(res.Keys) == limit {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.WithStack(err)
		}
		key, err := lib.keyInfoOfObject(sh, handle, details)
		if err != nil {
			return nil, err
		}
		examined++
		if search.match(key) {
			res.Keys = append(res.Keys, *key)
		}
	}
	if examined < len(handles) || more {
		res.NextPageToken, err = cryptoprov.NewPageToken(req, cryptoprov.PageCursor{Offset: offset + examined})
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// findObjectsWindow runs the search for template and returns the handles at
// positions offset to offset+window-1 of its order, and whether the search
// has objects after them. The search is finished before it returns, so the
// session is free for attribute reads.
func (lib *PKCS11Lib) findObjectsWindow(ctx context.Context, sh pkcs11.SessionHandle, template []*pkcs11.Attribute, offset, window int) (handles []pkcs11.ObjectHandle, more bool, err error) {
	if err := lib.Ctx.FindObjectsInit(sh, template); err != nil {
		return nil, false, errors.WithStack(err)
	}
	defer func() {
		_ = lib.Ctx.FindObjectsFinal(sh)
	}()

	skip := offset
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, errors.WithStack(err)
		}
		// one more than the window tells whether the search goes on
		want := min(findObjectsBatchSize, skip+window-len(handles)+1)
		batch, _, err := lib.Ctx.FindObjects(sh, want)
		if err != nil {
			return nil, false, errors.WithStack(err)
		}
		if len(batch) == 0 {
			return handles, false, nil
		}
		for _, handle := range batch {
			switch {
			case skip > 0:
				skip--
			case len(handles) < window:
				handles = append(handles, handle)
			default:
				return handles, true, nil
			}
		}
	}
}

// keyAttributesRead is a test hook that runs each time the attributes of a
// key object are read for a listing or for KeyInfo.
var keyAttributesRead = func() {}

// keyInfoOfObject reads the description of the key object handle: ID, label,
// type, class and the constant state, and with details the usage, the size
// and, for an ML-DSA key, the parameter set.
func (lib *PKCS11Lib) keyInfoOfObject(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, details bool) (*cryptoprov.KeyInfo, error) {
	keyAttributesRead()
	attributes, err := lib.Ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "GetAttributeValue on key")
	}

	keyID := string(attributes[0].Value)
	keyType, class, err := keyTypeAndClass(attributes[2], attributes[3])
	if err != nil {
		return nil, errors.WithMessagef(err, "key %q", keyID)
	}
	key := &cryptoprov.KeyInfo{
		ID:    keyID,
		Label: string(attributes[1].Value),
		Class: class,
		State: cryptoprov.KeyStateEnabled,
	}
	if _, ok := keyTypes[keyType]; ok {
		key.Type = keyType
	} else if keyType != "" {
		key.Meta = map[string]string{
			metaKeyType: keyType,
		}
	}
	if details {
		if err := lib.readKeyDetails(session, handle, key); err != nil {
			return nil, errors.WithMessagef(err, "key %q", keyID)
		}
	}
	return key, nil
}

// readKeyDetails sets the usage of key from CKA_SIGN and CKA_DECRYPT and its
// size from the attribute of its type: CKA_MODULUS, CKA_EC_PARAMS or
// CKA_PARAMETER_SET. They are read in one call; when the token refuses one
// of them (optionalAttributeErrors) they are read one by one and the
// refused ones are left out.
func (lib *PKCS11Lib) readKeyDetails(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, key *cryptoprov.KeyInfo) error {
	types := []uint{pkcs11.CKA_SIGN, pkcs11.CKA_DECRYPT}
	switch key.Type {
	case certutil.KeyTypeRSA:
		types = append(types, pkcs11.CKA_MODULUS)
	case certutil.KeyTypeECDSA:
		types = append(types, pkcs11.CKA_EC_PARAMS)
	case certutil.KeyTypeMLDSA:
		types = append(types, ckaParameterSet)
	}

	template := make([]*pkcs11.Attribute, len(types))
	for i, t := range types {
		template[i] = pkcs11.NewAttribute(t, nil)
	}
	values := make(map[uint][]byte, len(types))
	attributes, err := lib.Ctx.GetAttributeValue(session, handle, template)
	switch {
	case err == nil:
		for _, a := range attributes {
			values[a.Type] = a.Value
		}
	case isP11Error(err, optionalAttributeErrors):
		for _, t := range types {
			one, err := lib.Ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(t, nil)})
			if err != nil {
				if !isP11Error(err, optionalAttributeErrors) {
					return errors.WithMessage(err, "GetAttributeValue on key")
				}
				logger.KV(xlog.DEBUG, "reason", "attribute_unavailable", "attribute", t, "err", err)
				continue
			}
			values[t] = one[0].Value
		}
	default:
		return errors.WithMessage(err, "GetAttributeValue on key")
	}

	if isTrue(values[pkcs11.CKA_SIGN]) {
		key.Usage |= cryptoprov.KeyUsageSign
	}
	// only an RSA key decrypts: a token may set CKA_DECRYPT on a key of
	// another type by default, which grants nothing
	if key.Type == certutil.KeyTypeRSA && isTrue(values[pkcs11.CKA_DECRYPT]) {
		key.Usage |= cryptoprov.KeyUsageEncrypt
	}
	switch key.Type {
	case certutil.KeyTypeRSA:
		key.Size = new(big.Int).SetBytes(values[pkcs11.CKA_MODULUS]).BitLen()
	case certutil.KeyTypeECDSA:
		if curve, err := unmarshalEcParams(values[pkcs11.CKA_EC_PARAMS]); err == nil {
			key.Size = curve.Params().BitSize
		}
	case certutil.KeyTypeMLDSA:
		if set, err := bytesToUlong(values[ckaParameterSet]); err == nil {
			if params, ok := mldsaParameterSets[set]; ok {
				key.Size = mldsaSizes[set]
				key.Meta = map[string]string{
					cryptoprov.MetaParameterSet: params.String(),
				}
			}
		}
	}
	return nil
}

// isTrue reports whether value is a CK_BBOOL that is CK_TRUE.
func isTrue(value []byte) bool {
	return len(value) > 0 && value[0] != 0
}

func (lib *PKCS11Lib) keyInfoOnSlot(ctx context.Context, slotID uint, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	if err := fields.Validate(); err != nil {
		return nil, err
	}
	var res *cryptoprov.KeyInfo
	err := lib.withSessionCtx(ctx, slotID, func(session pkcs11.SessionHandle) error {
		var err error
		res, err = lib.keyInfoOnSession(session, slotID, keyID, fields.Has(cryptoprov.KeyFieldPublicKey))
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (lib *PKCS11Lib) keyInfoOnSession(session pkcs11.SessionHandle, slotID uint, keyID string, includePublic bool) (*cryptoprov.KeyInfo, error) {
	privHandle, err := lib.findKey(session, keyID, "", pkcs11.CKO_PRIVATE_KEY, ^uint(0))
	if err != nil {
		return nil, keyError(err, "private key %q", keyID)
	}
	key, err := lib.keyInfoOfObject(session, privHandle, true)
	if err != nil {
		return nil, err
	}
	if includePublic {
		key.PublicKey, err = lib.getPublicKeyPEM(session, slotID, key.ID)
		if err != nil {
			return nil, keyError(err, "reason='failed on GetPublicKey', slotID=%d, keyID=%q", slotID, key.ID)
		}
	}
	return key, nil
}

func (lib *PKCS11Lib) destroyKeyOnSlot(ctx context.Context, slotID uint, keyID string) error {
	err := lib.withSessionCtx(ctx, slotID, func(session pkcs11.SessionHandle) error {
		return lib.destroyKeyPairOnSession(session, slotID, keyID)
	})
	if err != nil {
		return keyError(err, "unable to destroy key %q", keyID)
	}
	return nil
}
