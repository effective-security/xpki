package awskmscrypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uuid"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/require"
)

const (
	fakeRegion  = "us-west-2"
	fakeAccount = "111122223333"
	fakeArnBase = "arn:aws:kms:" + fakeRegion + ":" + fakeAccount + ":"

	// defaultListKeysLimit is the KMS ListKeys page size without Limit.
	defaultListKeysLimit = 100
	deletionWindow       = 30 * 24 * time.Hour
)

// fakeKMS is an in-memory KmsClient: it creates, lists, describes and signs
// keys with real local key pairs the way KMS does, records its calls, and
// lets a test replace a method or slow down and fail DescribeKey. Its
// methods are safe for concurrent use; the override and hook fields are
// set before a provider call and not changed while one is in flight.
type fakeKMS struct {
	mu      sync.Mutex
	keys    map[string]*fakeKey // by key id
	order   []string            // key ids in creation order, the ListKeys order
	aliases map[string]string   // alias name to key id
	calls   map[string]int
	signed  []*kms.SignInput

	// A set override replaces the default behaviour of its method.
	createKey           func(*kms.CreateKeyInput) (*kms.CreateKeyOutput, error)
	createAlias         func(*kms.CreateAliasInput) (*kms.CreateAliasOutput, error)
	listKeys            func(*kms.ListKeysInput) (*kms.ListKeysOutput, error)
	scheduleKeyDeletion func(*kms.ScheduleKeyDeletionInput) (*kms.ScheduleKeyDeletionOutput, error)
	describeKey         func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
	getPublicKey        func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	sign                func(*kms.SignInput) (*kms.SignOutput, error)

	// describeDelay is how long a default DescribeKey takes. describeErr,
	// when set, is called with the key id and the 1-based number of the
	// DescribeKey call, and a non-nil result fails that call. listErr does
	// the same for the default ListKeys with the 1-based page number.
	describeDelay time.Duration
	describeErr   func(keyID string, call int) error
	listErr       func(page int) error

	// inFlight and peak count the concurrent default DescribeKey calls.
	inFlight atomic.Int32
	peak     atomic.Int32
}

// fakeKey is a KMS key with its local key pair.
type fakeKey struct {
	meta types.KeyMetadata
	priv crypto.Signer
}

var _ awskmscrypto.KmsClient = (*fakeKMS)(nil)

// algorithmSchemes maps each KMS digest-signing algorithm to its hash and
// RSA padding.
var algorithmSchemes = map[types.SigningAlgorithmSpec]struct {
	hash crypto.Hash
	pss  bool
}{
	types.SigningAlgorithmSpecRsassaPssSha256:      {hash: crypto.SHA256, pss: true},
	types.SigningAlgorithmSpecRsassaPssSha384:      {hash: crypto.SHA384, pss: true},
	types.SigningAlgorithmSpecRsassaPssSha512:      {hash: crypto.SHA512, pss: true},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: {hash: crypto.SHA256},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha384: {hash: crypto.SHA384},
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha512: {hash: crypto.SHA512},
	types.SigningAlgorithmSpecEcdsaSha256:          {hash: crypto.SHA256},
	types.SigningAlgorithmSpecEcdsaSha384:          {hash: crypto.SHA384},
	types.SigningAlgorithmSpecEcdsaSha512:          {hash: crypto.SHA512},
}

// rsaSigningAlgorithms are the algorithms of a SIGN_VERIFY RSA key, in the
// order KMS reports them.
var rsaSigningAlgorithms = []types.SigningAlgorithmSpec{
	types.SigningAlgorithmSpecRsassaPssSha256,
	types.SigningAlgorithmSpecRsassaPssSha384,
	types.SigningAlgorithmSpecRsassaPssSha512,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
}

// specAlgorithms maps a SIGN_VERIFY key spec to its signing algorithms.
var specAlgorithms = map[types.KeySpec][]types.SigningAlgorithmSpec{
	types.KeySpecRsa2048:     rsaSigningAlgorithms,
	types.KeySpecRsa3072:     rsaSigningAlgorithms,
	types.KeySpecRsa4096:     rsaSigningAlgorithms,
	types.KeySpecEccNistP256: {types.SigningAlgorithmSpecEcdsaSha256},
	types.KeySpecEccNistP384: {types.SigningAlgorithmSpecEcdsaSha384},
	types.KeySpecEccNistP521: {types.SigningAlgorithmSpecEcdsaSha512},
}

// rsaEncryptionAlgorithms are the algorithms of an ENCRYPT_DECRYPT RSA key.
var rsaEncryptionAlgorithms = []types.EncryptionAlgorithmSpec{
	types.EncryptionAlgorithmSpecRsaesOaepSha1,
	types.EncryptionAlgorithmSpecRsaesOaepSha256,
}

// keyPairs caches one local key pair per spec: generating RSA keys is slow
// and a fake key needs no unique material.
var (
	keyPairsMu sync.Mutex
	keyPairs   = map[types.KeySpec]crypto.Signer{}
)

// keyPair returns the local key pair for spec.
func keyPair(spec types.KeySpec) (crypto.Signer, error) {
	keyPairsMu.Lock()
	defer keyPairsMu.Unlock()
	if priv, ok := keyPairs[spec]; ok {
		return priv, nil
	}
	var priv crypto.Signer
	var err error
	switch spec {
	case types.KeySpecRsa2048:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case types.KeySpecRsa3072:
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case types.KeySpecRsa4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case types.KeySpecEccNistP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case types.KeySpecEccNistP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case types.KeySpecEccNistP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, validationError("unsupported key spec: " + string(spec))
	}
	if err != nil {
		return nil, err
	}
	keyPairs[spec] = priv
	return priv, nil
}

// validationError is the generic error KMS returns for an invalid request.
func validationError(message string) error {
	return &smithy.GenericAPIError{
		Code:    "ValidationException",
		Message: message,
		Fault:   smithy.FaultClient,
	}
}

// throttlingError is the error KMS returns when the request quota is
// exceeded; it is not modelled in the KMS types.
func throttlingError() error {
	return &smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "Rate exceeded",
		Fault:   smithy.FaultClient,
	}
}

func notFoundError(keyID string) error {
	return &types.NotFoundException{
		Message: aws.String("Key '" + keyID + "' does not exist"),
	}
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{
		keys:    map[string]*fakeKey{},
		aliases: map[string]string{},
		calls:   map[string]int{},
	}
}

func (f *fakeKMS) record(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[name]++
	return f.calls[name]
}

// CallCount returns how often the method name was called.
func (f *fakeKMS) CallCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

// SignRequests returns the default Sign requests so far.
func (f *fakeKMS) SignRequests() []*kms.SignInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*kms.SignInput(nil), f.signed...)
}

// addKey adds a key of spec and usage described by label, and returns its id.
func (f *fakeKMS) addKey(label string, spec types.KeySpec, usage types.KeyUsageType) (string, error) {
	if usage != types.KeyUsageTypeSignVerify && usage != types.KeyUsageTypeEncryptDecrypt {
		return "", validationError("unsupported key usage: " + string(usage))
	}
	if usage == types.KeyUsageTypeEncryptDecrypt && !strings.HasPrefix(string(spec), "RSA_") {
		return "", validationError("key spec " + string(spec) + " can not encrypt")
	}
	priv, err := keyPair(spec)
	if err != nil {
		return "", err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.NewV7().String()
	meta := types.KeyMetadata{
		KeyId:        aws.String(id),
		Arn:          aws.String(fakeArnBase + "key/" + id),
		AWSAccountId: aws.String(fakeAccount),
		CreationDate: aws.Time(time.Now().UTC().Truncate(time.Second)),
		Description:  aws.String(label),
		Enabled:      true,
		KeyState:     types.KeyStateEnabled,
		KeyUsage:     usage,
		KeySpec:      spec,
		Origin:       types.OriginTypeAwsKms,
		KeyManager:   types.KeyManagerTypeCustomer,
	}
	if usage == types.KeyUsageTypeSignVerify {
		meta.SigningAlgorithms = specAlgorithms[spec]
	} else {
		meta.EncryptionAlgorithms = rsaEncryptionAlgorithms
	}
	f.keys[id] = &fakeKey{
		meta: meta,
		priv: priv,
	}
	f.order = append(f.order, id)
	return id, nil
}

// mustAddKey is addKey, failing t on error.
func (f *fakeKMS) mustAddKey(t testing.TB, label string, spec types.KeySpec, usage types.KeyUsageType) string {
	t.Helper()
	id, err := f.addKey(label, spec, usage)
	require.NoError(t, err)
	return id
}

// keyCount returns the number of keys.
func (f *fakeKMS) keyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.order)
}

// setState sets the state of the key id.
func (f *fakeKMS) setState(id string, state types.KeyState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[id].meta.KeyState = state
	f.keys[id].meta.Enabled = state == types.KeyStateEnabled
}

// lookup resolves a key id, key ARN, alias name or alias ARN. The caller
// holds f.mu.
func (f *fakeKMS) lookup(keyID string) (*fakeKey, error) {
	id := strings.TrimPrefix(keyID, fakeArnBase+"key/")
	if alias, ok := strings.CutPrefix(id, fakeArnBase); ok {
		id = alias
	}
	if target, ok := f.aliases[id]; ok {
		id = target
	}
	key, ok := f.keys[id]
	if !ok {
		return nil, notFoundError(keyID)
	}
	return key, nil
}

func (f *fakeKMS) CreateKey(_ context.Context, req *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	f.record("CreateKey")
	if f.createKey != nil {
		return f.createKey(req)
	}
	id, err := f.addKey(aws.ToString(req.Description), req.KeySpec, req.KeyUsage)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	meta := f.keys[id].meta
	return &kms.CreateKeyOutput{KeyMetadata: &meta}, nil
}

func (f *fakeKMS) CreateAlias(_ context.Context, req *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	f.record("CreateAlias")
	if f.createAlias != nil {
		return f.createAlias(req)
	}
	alias := aws.ToString(req.AliasName)
	if !strings.HasPrefix(alias, "alias/") || strings.HasPrefix(alias, "alias/aws/") {
		return nil, &types.InvalidAliasNameException{Message: aws.String("invalid alias: " + alias)}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.aliases[alias]; exists {
		return nil, &types.AlreadyExistsException{Message: aws.String("alias exists: " + alias)}
	}
	target := aws.ToString(req.TargetKeyId)
	if _, ok := f.keys[target]; !ok {
		return nil, notFoundError(target)
	}
	f.aliases[alias] = target
	return &kms.CreateAliasOutput{}, nil
}

func (f *fakeKMS) ListKeys(_ context.Context, req *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	page := f.record("ListKeys")
	if f.listKeys != nil {
		return f.listKeys(req)
	}
	if f.listErr != nil {
		if err := f.listErr(page); err != nil {
			return nil, err
		}
	}
	limit := defaultListKeysLimit
	if req.Limit != nil {
		limit = int(*req.Limit)
		if limit < 1 || limit > awskmscrypto.ListKeysLimit {
			return nil, validationError(fmt.Sprintf("invalid limit: %d", limit))
		}
	}
	start := 0
	if req.Marker != nil {
		var err error
		if start, err = strconv.Atoi(*req.Marker); err != nil || start < 0 {
			return nil, &types.InvalidMarkerException{Message: aws.String("invalid marker")}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	start = min(start, len(f.order))
	end := min(start+limit, len(f.order))
	out := &kms.ListKeysOutput{}
	for _, id := range f.order[start:end] {
		out.Keys = append(out.Keys, types.KeyListEntry{
			KeyId:  aws.String(id),
			KeyArn: f.keys[id].meta.Arn,
		})
	}
	if end < len(f.order) {
		out.Truncated = true
		out.NextMarker = aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeKMS) ScheduleKeyDeletion(_ context.Context, req *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	f.record("ScheduleKeyDeletion")
	if f.scheduleKeyDeletion != nil {
		return f.scheduleKeyDeletion(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, err := f.lookup(aws.ToString(req.KeyId))
	if err != nil {
		return nil, err
	}
	key.meta.KeyState = types.KeyStatePendingDeletion
	key.meta.Enabled = false
	key.meta.DeletionDate = aws.Time(aws.ToTime(key.meta.CreationDate).Add(deletionWindow))
	return &kms.ScheduleKeyDeletionOutput{
		KeyId:        key.meta.Arn,
		KeyState:     key.meta.KeyState,
		DeletionDate: key.meta.DeletionDate,
	}, nil
}

func (f *fakeKMS) DescribeKey(ctx context.Context, req *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	call := f.record("DescribeKey")
	if f.describeKey != nil {
		return f.describeKey(req)
	}

	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		peak := f.peak.Load()
		if n <= peak || f.peak.CompareAndSwap(peak, n) {
			break
		}
	}

	keyID := aws.ToString(req.KeyId)
	if f.describeErr != nil {
		if err := f.describeErr(keyID, call); err != nil {
			return nil, err
		}
	}
	if f.describeDelay > 0 {
		select {
		case <-time.After(f.describeDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	key, err := f.lookup(keyID)
	if err != nil {
		return nil, err
	}
	meta := key.meta
	return &kms.DescribeKeyOutput{KeyMetadata: &meta}, nil
}

func (f *fakeKMS) GetPublicKey(_ context.Context, req *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.record("GetPublicKey")
	if f.getPublicKey != nil {
		return f.getPublicKey(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, err := f.lookup(aws.ToString(req.KeyId))
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.priv.Public())
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:                key.meta.Arn,
		KeySpec:              key.meta.KeySpec,
		KeyUsage:             key.meta.KeyUsage,
		PublicKey:            der,
		SigningAlgorithms:    key.meta.SigningAlgorithms,
		EncryptionAlgorithms: key.meta.EncryptionAlgorithms,
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, req *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.record("Sign")
	if f.sign != nil {
		return f.sign(req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signed = append(f.signed, req)

	key, err := f.lookup(aws.ToString(req.KeyId))
	if err != nil {
		return nil, err
	}
	switch key.meta.KeyState {
	case types.KeyStateEnabled:
	case types.KeyStateDisabled:
		return nil, &types.DisabledException{Message: aws.String("key is disabled")}
	default:
		return nil, &types.KMSInvalidStateException{Message: aws.String("key is " + string(key.meta.KeyState))}
	}
	algorithm := req.SigningAlgorithm
	if key.meta.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, &types.InvalidKeyUsageException{Message: aws.String("key usage is " + string(key.meta.KeyUsage))}
	}
	if !slices.Contains(key.meta.SigningAlgorithms, algorithm) {
		return nil, &types.InvalidKeyUsageException{Message: aws.String("algorithm " + string(algorithm) + " is not valid for the key")}
	}
	if req.MessageType != types.MessageTypeDigest {
		return nil, validationError("only DIGEST messages are supported")
	}
	scheme := algorithmSchemes[algorithm]
	if len(req.Message) != scheme.hash.Size() {
		return nil, validationError("Digest is invalid length for algorithm " + string(algorithm))
	}

	var opts crypto.SignerOpts = scheme.hash
	if scheme.pss {
		opts = &rsa.PSSOptions{
			Hash:       scheme.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
	}
	sig, err := key.priv.Sign(rand.Reader, req.Message, opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &kms.SignOutput{
		KeyId:            key.meta.Arn,
		Signature:        sig,
		SigningAlgorithm: algorithm,
	}, nil
}

// testTokenCfg is the token config of test providers.
func testTokenCfg() *mockTokenCfg {
	return &mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
	}
}

// newProvider returns a provider over client.
func newProvider(t testing.TB, client awskmscrypto.KmsClient) *awskmscrypto.Provider {
	t.Helper()
	return awskmscrypto.NewTestProvider(testTokenCfg(), client)
}

//
// mockTokenCfg
//

type mockTokenCfg struct {
	manufacturer string
	model        string
	path         string
	tokenSerial  string
	tokenLabel   string
	pin          string
	atts         string
}

// Manufacturer name of the manufacturer
func (m *mockTokenCfg) Manufacturer() string {
	return m.manufacturer
}

// Model name of the device
func (m *mockTokenCfg) Model() string {
	return m.model
}

// Full path to PKCS#11 library
func (m *mockTokenCfg) Path() string {
	return m.path
}

// Token serial number
func (m *mockTokenCfg) TokenSerial() string {
	return m.tokenSerial
}

// Token label
func (m *mockTokenCfg) TokenLabel() string {
	return m.tokenLabel
}

// Pin is a secret to access the token.
// If it's prefixed with `file:`, then it will be loaded from the file.
func (m *mockTokenCfg) Pin() string {
	return m.pin
}

// Comma separated key=value pair of attributes(e.g. "ServiceName=x,UserName=y")
func (m *mockTokenCfg) Attributes() string {
	return m.atts
}
