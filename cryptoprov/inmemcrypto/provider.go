package inmemcrypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"uuid"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "inmemcrypto")

// ProviderName specifies a provider name
const ProviderName = "inmem"

func init() {
	_ = cryptoprov.Register(ProviderName, Loader)
}

// inMemProv stores keyID to signer mapping in memory.
// Private keys are exportable.
type inMemProv struct {
	mu         sync.RWMutex
	keyIDToPvk map[string]crypto.PrivateKey
	// order has the key ids in the order they were registered, which is the
	// order of a listing.
	order []string
}

// registerKey registers key for the given id in HSM
func (h *inMemProv) registerKey(keyID string, pvk crypto.PrivateKey) {
	logger.KV(xlog.TRACE, "id", keyID)
	h.mu.Lock()
	if _, ok := h.keyIDToPvk[keyID]; !ok {
		h.order = append(h.order, keyID)
	}
	h.keyIDToPvk[keyID] = pvk
	h.mu.Unlock()
}

// getKey returns the registered signer for the given key id, or a wrapped
// cryptoprov.ErrKeyNotFound.
func (h *inMemProv) getKey(keyID string) (crypto.PrivateKey, error) {
	h.mu.RLock()
	pvk, ok := h.keyIDToPvk[keyID]
	h.mu.RUnlock()
	if !ok {
		return nil, errKeyNotFound(keyID)
	}
	return pvk, nil
}

// errKeyNotFound returns the error for a key the provider does not have,
// which errors.Is matches with cryptoprov.ErrKeyNotFound.
func errKeyNotFound(keyID string) error {
	return cryptoprov.MarkError(errors.Errorf("key not found: %s", keyID), cryptoprov.ErrKeyNotFound)
}

// removeKey forgets the key keyID and reports whether it was registered.
func (h *inMemProv) removeKey(keyID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.keyIDToPvk[keyID]; !ok {
		return false
	}
	delete(h.keyIDToPvk, keyID)
	h.order = slices.DeleteFunc(h.order, func(id string) bool {
		return id == keyID
	})
	return true
}

// keys returns the registered keys in registration order.
func (h *inMemProv) keys() []crypto.PrivateKey {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := make([]crypto.PrivateKey, 0, len(h.order))
	for _, id := range h.order {
		list = append(list, h.keyIDToPvk[id])
	}
	return list
}

// provImpl is the handle of a key: its fields are set once, before the key
// is registered.
type provImpl struct {
	id      string
	label   string
	pvk     crypto.PrivateKey
	usage   cryptoprov.KeyUsage
	tags    map[string]string
	created time.Time
}

// KeyID returns key id of the signer
func (s *provImpl) KeyID() string {
	return s.id
}

// Label returns key label of the signer
func (s *provImpl) Label() string {
	return s.label
}

// Public returns public key of the signer
func (s *provImpl) Public() crypto.PublicKey {
	if signer, ok := s.pvk.(crypto.Signer); ok {
		return signer.Public()
	} else if decrypter, ok := s.pvk.(crypto.Decrypter); ok {
		return decrypter.Public()
	}
	return s.pvk
}

// Sign signs digest with the key. For an RSA or ECDSA key nil opts mean
// crypto.SHA256. An ML-DSA key signs the message: it accepts nil, a zero
// hash, *mldsa.Options or crypto.MLDSAMu and rejects every digest hash
// (cryptoprov.MLDSASignerOptions).
func (s *provImpl) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, ok := s.pvk.(crypto.Signer)
	if !ok {
		return nil, errors.Errorf("crypto.Signer is not supported")
	}
	if _, isMLDSA := s.pvk.(*mldsa.PrivateKey); isMLDSA {
		return signMLDSA(signer, digest, opts)
	}
	if opts == nil {
		opts = crypto.SHA256
	}
	return signer.Sign(rand, digest, opts)
}

// signMLDSA validates opts against the ML-DSA signer contract and signs
// with the in-memory key, which hedges its signatures (FIPS 204 default).
func signMLDSA(signer crypto.Signer, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	mu, context, err := cryptoprov.MLDSASignerOptions(opts)
	if err != nil {
		return nil, err
	}
	var keyOpts crypto.SignerOpts
	switch {
	case mu:
		keyOpts = crypto.MLDSAMu
	case context != "":
		keyOpts = &mldsa.Options{Context: context}
	}
	sig, err := signer.Sign(rand.Reader, message, keyOpts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sig, nil
}

// Decrypt decrypts ciphertext with an RSA key, as crypto.Decrypter of
// *rsa.PrivateKey does; a key of another type is an error.
func (s *provImpl) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if decrypter, ok := s.pvk.(crypto.Decrypter); ok {
		return decrypter.Decrypt(rand, ciphertext, opts)
	}

	return nil, errors.Errorf("crypto.Decrypter is not supported")
}

// info returns the description of the key, with every group a listing can
// fill; none of them costs anything here.
func (s *provImpl) info() cryptoprov.KeyInfo {
	ki := cryptoprov.KeyInfo{
		ID:    s.id,
		Label: s.label,
		Usage: s.usage,
		State: cryptoprov.KeyStateEnabled,
		Tags:  maps.Clone(s.tags),
	}
	if !s.created.IsZero() {
		created := s.created
		ki.CreationTime = &created
	}
	pub := s.Public()
	// a key registered directly by a test may be of an unsupported type
	if info, err := certutil.NewKeyInfo(pub); err == nil {
		ki.Type = info.Type
		ki.Size = info.KeySize
	}
	if mldsaPub, ok := pub.(*mldsa.PublicKey); ok {
		ki.Meta = map[string]string{
			cryptoprov.MetaParameterSet: mldsaPub.Parameters().String(),
		}
	}
	return ki
}

type rsaKeyGenerator interface {
	GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error)
}

type defaultRsaKeyGenerator struct {
}

func (g *defaultRsaKeyGenerator) GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(random, bits)
}

type ecdsaKeyGenerator interface {
	GenerateKey(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error)
}

type defaultEcdsaKeyGenerator struct {
}

func (g *defaultEcdsaKeyGenerator) GenerateKey(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(c, rand)
}

type mldsaKeyGenerator interface {
	GenerateKey(params mldsa.Parameters) (*mldsa.PrivateKey, error)
}

type defaultMLDSAKeyGenerator struct {
}

func (g *defaultMLDSAKeyGenerator) GenerateKey(params mldsa.Parameters) (*mldsa.PrivateKey, error) {
	return mldsa.GenerateKey(params)
}

type idGenerator interface {
	Generate() string
}

type defaultIDGenerator struct {
}

func (g *defaultIDGenerator) Generate() string {
	return uuid.NewV7().String()
}

// Provider stores exportable RSA, ECDSA and ML-DSA keys and supports
// concurrent key generation, lookup, and PEM export. Token configuration
// must remain unchanged while the provider is in use.
type Provider struct {
	idGenerator
	rsaKeyGenerator
	ecdsaKeyGenerator
	mldsaKeyGenerator
	inMemProv *inMemProv
	tc        cryptoprov.TokenConfig
}

// NewProvider creates new provider for exportable RSA, ECDSA and ML-DSA
// keys. This provider should be used only when HSM use is not applicable.
func NewProvider() *Provider {
	inMemProv := inMemProv{
		keyIDToPvk: make(map[string]crypto.PrivateKey),
	}

	return &Provider{
		inMemProv:         &inMemProv,
		rsaKeyGenerator:   &defaultRsaKeyGenerator{},
		ecdsaKeyGenerator: &defaultEcdsaKeyGenerator{},
		mldsaKeyGenerator: &defaultMLDSAKeyGenerator{},
		idGenerator:       &defaultIDGenerator{},
	}
}

// Manufacturer return manufacturer for the provider
func (p *Provider) Manufacturer() string {
	if p.tc != nil {
		return p.tc.Manufacturer()
	}
	return ProviderName
}

// Model return model for the provider
func (p *Provider) Model() string {
	if p.tc != nil {
		return p.tc.Model()
	}
	return ProviderName
}

// Serial return serial number for the provider
func (p *Provider) Serial() string {
	if p.tc != nil {
		return p.tc.TokenSerial()
	}
	return "23948570247520345"
}

// GetKey returns key for the given id, or a wrapped
// cryptoprov.ErrKeyNotFound.
func (p *Provider) GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	pvk, err := p.inMemProv.getKey(keyID)
	if err != nil {
		return nil, errors.WithMessagef(err, "key not found: %s", keyID)
	}
	return pvk, nil
}

// GenerateKey creates a signer using a randomly generated RSA, ECDSA or
// ML-DSA key as req describes it (cryptoprov.GenerateKeyRequest.Validate).
// An ML-DSA signer signs messages, not digests; see
// cryptoprov.MLDSASignerOptions. The usage and the tags are recorded for
// KeyInfo and ListKeys and are not enforced. An empty label gets a random
// one.
func (p *Provider) GenerateKey(ctx context.Context, req *cryptoprov.GenerateKeyRequest) (crypto.PrivateKey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	var (
		key crypto.PrivateKey
		err error
	)
	switch req.Type {
	case certutil.KeyTypeRSA:
		key, err = p.rsaKeyGenerator.GenerateKey(rand.Reader, req.Size)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to generate key, bit size: %d", req.Size)
		}
	case certutil.KeyTypeECDSA:
		var curve elliptic.Curve
		if curve, err = cryptoprov.ECDSACurve(req.Size); err != nil {
			return nil, err
		}
		key, err = p.ecdsaKeyGenerator.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to generate key, curve: %d", req.Size)
		}
	default: // certutil.KeyTypeMLDSA, the only other type Validate accepts
		var params mldsa.Parameters
		if params, err = cryptoprov.MLDSAParameters(req.Size); err != nil {
			return nil, err
		}
		key, err = p.mldsaKeyGenerator.GenerateKey(params)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to generate key, parameter set: %s", params)
		}
	}

	label := req.Label
	if len(label) == 0 {
		label = uuid.NewV7().String()
	}

	id := p.Generate()

	si := &provImpl{
		id:      id,
		label:   label,
		pvk:     key,
		usage:   req.KeyUsage(),
		tags:    maps.Clone(req.Tags),
		created: time.Now().UTC(),
	}
	p.inMemProv.registerKey(id, si)
	return si, nil
}

// IdentifyKey returns key id and label for the given private key
func (p *Provider) IdentifyKey(_ context.Context, priv crypto.PrivateKey) (keyID, label string, err error) {
	if ki, ok := priv.(*provImpl); ok {
		return ki.KeyID(), ki.Label(), nil
	}
	return "", "", errors.Errorf("unsupported key: %T", priv)
}

// ListKeys returns a page of the keys in the order they were generated; the
// page token is an offset in that order (cryptoprov.PageKeys). Every field
// group is filled whatever req.Fields selects, since none costs a request.
func (p *Provider) ListKeys(ctx context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	keys := p.inMemProv.keys()
	infos := make([]cryptoprov.KeyInfo, 0, len(keys))
	for _, key := range keys {
		if si, ok := key.(*provImpl); ok {
			infos = append(infos, si.info())
		}
	}
	return cryptoprov.PageKeys(req, infos)
}

// KeyInfo describes the key keyID, with its PEM public key when fields has
// cryptoprov.KeyFieldPublicKey. A key the provider does not have is a
// wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) KeyInfo(ctx context.Context, keyID string, fields cryptoprov.KeyFields) (*cryptoprov.KeyInfo, error) {
	if err := fields.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := p.inMemProv.getKey(keyID)
	if err != nil {
		return nil, err
	}
	si, ok := key.(*provImpl)
	if !ok {
		return nil, errors.Errorf("unsupported key %T: %s", key, keyID)
	}
	ki := si.info()
	if fields.Has(cryptoprov.KeyFieldPublicKey) {
		pemKey, err := certutil.EncodePublicKeyToPEM(si.Public())
		if err != nil {
			return nil, errors.WithMessagef(err, "public key: %s", keyID)
		}
		ki.PublicKey = string(pemKey)
	}
	return &ki, nil
}

// DestroyKey forgets the key keyID. Handles returned earlier keep working.
// A key the provider does not have is a wrapped cryptoprov.ErrKeyNotFound.
func (p *Provider) DestroyKey(ctx context.Context, keyID string) error {
	if err := ctx.Err(); err != nil {
		return errors.WithStack(err)
	}
	if !p.inMemProv.removeKey(keyID) {
		return errKeyNotFound(keyID)
	}
	return nil
}

// ExportKey returns the PEM encoded plain text key: PKCS#1 for RSA, SEC1
// for ECDSA and PKCS#8 (seed form) for ML-DSA.
func (p *Provider) ExportKey(_ context.Context, keyID string) (string, []byte, error) {
	var key []byte

	prov, err := p.inMemProv.getKey(keyID)
	if err != nil {
		return "", nil, errors.WithMessagef(err, "unable to get key: %s", keyID)
	}

	priv := prov.(*provImpl).pvk

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		key = x509.MarshalPKCS1PrivateKey(priv)
		block := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	case *ecdsa.PrivateKey:
		key, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			return "", nil, errors.WithMessagef(err, "export EC key: %s", keyID)
		}
		block := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	case *mldsa.PrivateKey:
		key, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", nil, errors.WithMessagef(err, "export ML-DSA key: %s", keyID)
		}
		block := pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	default:
		// the generators register only the types above
		return "", nil, errors.Errorf("unsupported key type %T: %s", priv, keyID)
	}

	return "", key, nil
}

// Ensure compiles
var _ cryptoprov.Provider = (*Provider)(nil)
var _ cryptoprov.KeyManager = (*Provider)(nil)

// Loader provides loader for Provider
func Loader(tc cryptoprov.TokenConfig) (cryptoprov.Provider, error) {
	p := NewProvider()
	p.tc = tc
	return p, nil
}
