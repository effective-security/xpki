package gcpkmscrypto_test

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
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/v2/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	testKeyring     = "projects/test/locations/global/keyRings/versions"
	cryptoKeysPath  = "/cryptoKeys/"
	versionsPath    = "/cryptoKeyVersions/"
	fakeDestroyWait = 24 * time.Hour
	// fakeVersionPageSize caps a ListCryptoKeyVersions page, so a client that
	// leaves PageSize at zero must follow page tokens.
	fakeVersionPageSize = 2
	// fakeKeyPageSize is the ListCryptoKeys page size without PageSize.
	fakeKeyPageSize = 100
)

// KMS limits on a CryptoKey id and a label key or value.
var (
	keyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9_-]{0,63}$`)
)

// fakeVersion is a key version of fakeKMSServer with its local private key.
type fakeVersion struct {
	pb     *kmspb.CryptoKeyVersion
	signer crypto.Signer
	// pending is how many GetCryptoKeyVersion calls still report
	// PENDING_GENERATION.
	pending int
}

// fakeKMSServer is an in-process KMS over gRPC with real local keys, so the
// real SDK client, its iterators and the signatures can be checked. Its
// checks of ids, labels, states and digests follow the KMS documentation.
type fakeKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer

	mu       sync.Mutex
	keys     map[string]*kmspb.CryptoKey // by resource name
	versions map[string][]*fakeVersion   // by key resource name, index = version-1

	// pendingPolls is how many GetCryptoKeyVersion calls a version created
	// by CreateCryptoKey answers with PENDING_GENERATION before finalState.
	pendingPolls int
	// finalState is the state such a version reaches, ENABLED by default.
	finalState kmspb.CryptoKeyVersion_CryptoKeyVersionState
	// createErrors are returned by CreateCryptoKey, in order, before it
	// creates anything.
	createErrors []error
	// destroyErrors are returned by DestroyCryptoKeyVersion for the version
	// resource names they are keyed by.
	destroyErrors map[string]error

	calls     []string
	createIDs []string
	// listRequests are the ListCryptoKeys requests so far.
	listRequests []*kmspb.ListCryptoKeysRequest
	// versionListErrors are returned by ListCryptoKeyVersions for the key
	// resource names they are keyed by.
	versionListErrors map[string]error
}

func newFakeKMSServer() *fakeKMSServer {
	return &fakeKMSServer{
		keys:       map[string]*kmspb.CryptoKey{},
		versions:   map[string][]*fakeVersion{},
		finalState: kmspb.CryptoKeyVersion_ENABLED,
	}
}

// Calls returns the RPC method names called so far.
func (s *fakeKMSServer) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// CallCount returns how often the RPC method name was called.
func (s *fakeKMSServer) CallCount(name string) int {
	count := 0
	for _, call := range s.Calls() {
		if call == name {
			count++
		}
	}
	return count
}

// CreateIDs returns the CryptoKeyId of every CreateCryptoKey request.
func (s *fakeKMSServer) CreateIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.createIDs...)
}

// AddKey creates the key id in testKeyring with one ENABLED version of
// algorithm, labelled label, and returns the key's resource name.
func (s *fakeKMSServer) AddKey(t *testing.T, id string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, label string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	name := testKeyring + cryptoKeysPath + id
	require.NotContains(t, s.keys, name)
	s.keys[name] = &kmspb.CryptoKey{
		Name:       name,
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		CreateTime: timestamppb.Now(),
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			Algorithm:       algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		Labels: map[string]string{
			"label": label,
		},
	}
	_, err := s.addVersionLocked(name, algorithm, kmspb.CryptoKeyVersion_ENABLED, 0)
	require.NoError(t, err)
	return name
}

// AddVersion adds a version of the key resource name keyName in state with
// a fresh local key of algorithm and returns the version's resource name.
func (s *fakeKMSServer) AddVersion(t *testing.T, keyName string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, state kmspb.CryptoKeyVersion_CryptoKeyVersionState) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Contains(t, s.keys, keyName)
	v, err := s.addVersionLocked(keyName, algorithm, state, 0)
	require.NoError(t, err)
	return v.pb.GetName()
}

// SetState sets the state of the version resource name.
func (s *fakeKMSServer) SetState(t *testing.T, name string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.versionLocked(name)
	require.NotNil(t, v, name)
	v.pb.State = state
}

// FailDestroy makes DestroyCryptoKeyVersion of the version resource name
// return err; a nil err clears it.
func (s *fakeKMSServer) FailDestroy(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyErrors == nil {
		s.destroyErrors = map[string]error{}
	}
	if err == nil {
		delete(s.destroyErrors, name)
		return
	}
	s.destroyErrors[name] = err
}

// State returns the state of the version resource name.
func (s *fakeKMSServer) State(t *testing.T, name string) kmspb.CryptoKeyVersion_CryptoKeyVersionState {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.versionLocked(name)
	require.NotNil(t, v, name)
	return v.pb.GetState()
}

// PublicKey returns the public key of the version resource name.
func (s *fakeKMSServer) PublicKey(t *testing.T, name string) crypto.PublicKey {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.versionLocked(name)
	require.NotNil(t, v, name)
	return v.signer.Public()
}

func (s *fakeKMSServer) record(name string) {
	s.calls = append(s.calls, name)
}

func (s *fakeKMSServer) versionLocked(name string) *fakeVersion {
	keyName, number, found := strings.Cut(name, versionsPath)
	if !found {
		return nil
	}
	index, err := strconv.Atoi(number)
	versions := s.versions[keyName]
	if err != nil || index < 1 || index > len(versions) {
		return nil
	}
	return versions[index-1]
}

func (s *fakeKMSServer) addVersionLocked(keyName string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, state kmspb.CryptoKeyVersion_CryptoKeyVersionState, pending int) (*fakeVersion, error) {
	signer, err := newLocalKey(algorithm)
	if err != nil {
		return nil, err
	}
	number := len(s.versions[keyName]) + 1
	v := &fakeVersion{
		pb: &kmspb.CryptoKeyVersion{
			Name:            keyName + versionsPath + strconv.Itoa(number),
			State:           state,
			Algorithm:       algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
			CreateTime:      timestamppb.Now(),
		},
		signer:  signer,
		pending: pending,
	}
	s.versions[keyName] = append(s.versions[keyName], v)
	return v, nil
}

// algorithmScheme is the test's own table of each signing algorithm's
// digest hash and padding, independent of the provider's.
func algorithmScheme(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (hash crypto.Hash, pss bool, ok bool) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return crypto.SHA256, false, true
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384, false, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return crypto.SHA256, false, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return crypto.SHA512, false, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		return crypto.SHA256, true, true
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return crypto.SHA512, true, true
	default:
		return 0, false, false
	}
}

// mldsaAlgorithm is the test's own table of the ML-DSA algorithms: the
// parameter set and whether KMS takes μ (EXTERNAL_MU) or the message.
func mldsaAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (params mldsa.Parameters, externalMu bool, ok bool) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44:
		return mldsa.MLDSA44(), false, true
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65:
		return mldsa.MLDSA65(), false, true
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87:
		return mldsa.MLDSA87(), false, true
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU:
		return mldsa.MLDSA44(), true, true
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU:
		return mldsa.MLDSA65(), true, true
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU:
		return mldsa.MLDSA87(), true, true
	default:
		return mldsa.Parameters{}, false, false
	}
}

// mldsaMuSize is the length of the μ an EXTERNAL_MU algorithm accepts.
const mldsaMuSize = 64

var (
	rsaKeysMu sync.Mutex
	rsaKeys   = map[int]*rsa.PrivateKey{}
)

// testRSAKey returns one RSA key per size, generated once per process.
func testRSAKey(bits int) (*rsa.PrivateKey, error) {
	rsaKeysMu.Lock()
	defer rsaKeysMu.Unlock()
	if key, ok := rsaKeys[bits]; ok {
		return key, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	rsaKeys[bits] = key
	return key, nil
}

func newLocalKey(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.Signer, error) {
	if params, _, ok := mldsaAlgorithm(algorithm); ok {
		return mldsa.GenerateKey(params)
	}
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:
		return testRSAKey(2048)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:
		return testRSAKey(3072)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return testRSAKey(4096)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm %s", algorithm)
	}
}

func (s *fakeKMSServer) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("CreateCryptoKey")
	s.createIDs = append(s.createIDs, req.GetCryptoKeyId())
	if len(s.createErrors) > 0 {
		err := s.createErrors[0]
		s.createErrors = s.createErrors[1:]
		return nil, err
	}
	if req.GetParent() != testKeyring {
		return nil, status.Errorf(codes.NotFound, "key ring %q not found", req.GetParent())
	}
	if !keyIDPattern.MatchString(req.GetCryptoKeyId()) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid crypto key id %q", req.GetCryptoKeyId())
	}
	for k, v := range req.GetCryptoKey().GetLabels() {
		if !labelPattern.MatchString(k) || !labelPattern.MatchString(v) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid label %q=%q", k, v)
		}
	}
	name := testKeyring + cryptoKeysPath + req.GetCryptoKeyId()
	if _, ok := s.keys[name]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "crypto key %q already exists", name)
	}
	if req.GetCryptoKey().GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported purpose %s", req.GetCryptoKey().GetPurpose())
	}
	key := proto.Clone(req.GetCryptoKey()).(*kmspb.CryptoKey)
	key.Name = name
	key.CreateTime = timestamppb.Now()
	if _, err := s.addVersionLocked(name, key.GetVersionTemplate().GetAlgorithm(), s.finalState, s.pendingPolls); err != nil {
		return nil, err
	}
	s.keys[name] = key
	return proto.Clone(key).(*kmspb.CryptoKey), nil
}

func (s *fakeKMSServer) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("GetCryptoKey")
	key, ok := s.keys[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "crypto key %q not found", req.GetName())
	}
	return proto.Clone(key).(*kmspb.CryptoKey), nil
}

// FailCreate makes the next CreateCryptoKey calls fail with errs, in order.
func (s *fakeKMSServer) FailCreate(errs ...error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createErrors = append(s.createErrors, errs...)
}

// FailVersionListing makes ListCryptoKeyVersions of the key resource name
// fail with err.
func (s *fakeKMSServer) FailVersionListing(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versionListErrors == nil {
		s.versionListErrors = map[string]error{}
	}
	s.versionListErrors[name] = err
}

// ListRequests returns the ListCryptoKeys requests so far.
func (s *fakeKMSServer) ListRequests() []*kmspb.ListCryptoKeysRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.listRequests)
}

// SetLabels replaces the labels of the key resource name.
func (s *fakeKMSServer) SetLabels(t *testing.T, name string, labels map[string]string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Contains(t, s.keys, name)
	s.keys[name].Labels = labels
}

// AddSymmetricKey creates the ENCRYPT_DECRYPT key id in testKeyring, whose
// primary version is in state, and returns the key's resource name.
func (s *fakeKMSServer) AddSymmetricKey(t *testing.T, id, label string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	name := testKeyring + cryptoKeysPath + id
	require.NotContains(t, s.keys, name)
	s.keys[name] = &kmspb.CryptoKey{
		Name:       name,
		Purpose:    kmspb.CryptoKey_ENCRYPT_DECRYPT,
		CreateTime: timestamppb.Now(),
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		Labels: map[string]string{
			"label": label,
		},
		Primary: &kmspb.CryptoKeyVersion{
			Name:      name + "/cryptoKeyVersions/1",
			State:     state,
			Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		},
	}
	return name
}

// AddForeignKey creates the signing key id in testKeyring with one ENABLED
// version of an algorithm the fake has no key material for, such as
// secp256k1: it can be listed and described, not used.
func (s *fakeKMSServer) AddForeignKey(t *testing.T, id string, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, label string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	name := testKeyring + cryptoKeysPath + id
	require.NotContains(t, s.keys, name)
	s.keys[name] = &kmspb.CryptoKey{
		Name:       name,
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		CreateTime: timestamppb.Now(),
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			Algorithm:       algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		Labels: map[string]string{
			"label": label,
		},
	}
	s.versions[name] = append(s.versions[name], &fakeVersion{
		pb: &kmspb.CryptoKeyVersion{
			Name:            name + versionsPath + "1",
			State:           kmspb.CryptoKeyVersion_ENABLED,
			Algorithm:       algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
			CreateTime:      timestamppb.Now(),
		},
	})
	return name
}

// matchListFilter reports whether key passes filter, in the forms the KMS
// documentation gives for labels: "labels.k=v" for an exact value and
// "labels.k:v" for a case-insensitive substring, joined with " AND ". Any
// other filter is an error, so a test sees a form the provider should not
// send.
func matchListFilter(filter string, key *kmspb.CryptoKey) (bool, error) {
	if filter == "" {
		return true, nil
	}
	for term := range strings.SplitSeq(filter, " AND ") {
		field, ok := strings.CutPrefix(term, "labels.")
		if !ok {
			return false, status.Errorf(codes.InvalidArgument, "unsupported filter %q", term)
		}
		if name, value, ok := strings.Cut(field, "="); ok {
			if got, has := key.GetLabels()[name]; !has || got != value {
				return false, nil
			}
			continue
		}
		name, value, ok := strings.Cut(field, ":")
		if !ok {
			return false, status.Errorf(codes.InvalidArgument, "unsupported filter %q", term)
		}
		if !strings.Contains(strings.ToLower(key.GetLabels()[name]), strings.ToLower(value)) {
			return false, nil
		}
	}
	return true, nil
}

// ListCryptoKeys lists the keys of the parent in name order that pass the
// filter (matchListFilter), PageSize at most and fakeKeyPageSize by default;
// the page token is the index of the next key.
func (s *fakeKMSServer) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("ListCryptoKeys")
	s.listRequests = append(s.listRequests, proto.Clone(req).(*kmspb.ListCryptoKeysRequest))

	var matched []*kmspb.CryptoKey
	for _, name := range slices.Sorted(maps.Keys(s.keys)) {
		if !strings.HasPrefix(name, req.GetParent()+cryptoKeysPath) {
			continue
		}
		ok, err := matchListFilter(req.GetFilter(), s.keys[name])
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, s.keys[name])
		}
	}
	start := 0
	if token := req.GetPageToken(); token != "" {
		var err error
		if start, err = strconv.Atoi(token); err != nil || start < 0 || start > len(matched) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token %q", token)
		}
	}
	size := int(req.GetPageSize())
	if size <= 0 {
		size = fakeKeyPageSize
	}
	end := min(start+size, len(matched))
	resp := &kmspb.ListCryptoKeysResponse{
		TotalSize: int32(len(matched)),
	}
	for _, key := range matched[start:end] {
		resp.CryptoKeys = append(resp.CryptoKeys, proto.Clone(key).(*kmspb.CryptoKey))
	}
	if end < len(matched) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (s *fakeKMSServer) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("GetCryptoKeyVersion")
	v := s.versionLocked(req.GetName())
	if v == nil {
		return nil, status.Errorf(codes.NotFound, "crypto key version %q not found", req.GetName())
	}
	resp := proto.Clone(v.pb).(*kmspb.CryptoKeyVersion)
	if v.pending > 0 {
		v.pending--
		resp.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
	}
	return resp, nil
}

// ListCryptoKeyVersions pages by PageSize, at most fakeVersionPageSize per
// page; the page token is the index of the next version.
func (s *fakeKMSServer) ListCryptoKeyVersions(_ context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("ListCryptoKeyVersions")
	if err := s.versionListErrors[req.GetParent()]; err != nil {
		return nil, err
	}
	if _, ok := s.keys[req.GetParent()]; !ok {
		return nil, status.Errorf(codes.NotFound, "crypto key %q not found", req.GetParent())
	}
	versions := s.versions[req.GetParent()]
	start := 0
	if token := req.GetPageToken(); token != "" {
		var err error
		if start, err = strconv.Atoi(token); err != nil || start < 0 || start > len(versions) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page token %q", token)
		}
	}
	size := int(req.GetPageSize())
	if size <= 0 || size > fakeVersionPageSize {
		size = fakeVersionPageSize
	}
	end := min(start+size, len(versions))
	resp := &kmspb.ListCryptoKeyVersionsResponse{
		TotalSize: int32(len(versions)),
	}
	for _, v := range versions[start:end] {
		resp.CryptoKeyVersions = append(resp.CryptoKeyVersions, proto.Clone(v.pb).(*kmspb.CryptoKeyVersion))
	}
	if end < len(versions) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (s *fakeKMSServer) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("GetPublicKey")
	v := s.versionLocked(req.GetName())
	if v == nil {
		return nil, status.Errorf(codes.NotFound, "crypto key version %q not found", req.GetName())
	}
	if v.pending > 0 || v.pb.GetState() != kmspb.CryptoKeyVersion_ENABLED {
		return nil, status.Errorf(codes.FailedPrecondition, "crypto key version %q is not enabled", req.GetName())
	}
	// As the service does: a PQ version is returned only in the NIST_PQC
	// format, as raw bytes with a checksum and no PEM; a classical version
	// is returned as PEM unless another format is asked for.
	format := req.GetPublicKeyFormat()
	if _, _, ok := mldsaAlgorithm(v.pb.GetAlgorithm()); ok {
		if format != kmspb.PublicKey_NIST_PQC {
			return nil, status.Errorf(codes.InvalidArgument, "public_key_format NIST_PQC is required for algorithm %s", v.pb.GetAlgorithm())
		}
		raw := v.signer.Public().(*mldsa.PublicKey).Bytes()
		return &kmspb.PublicKey{
			Name:            req.GetName(),
			Algorithm:       v.pb.GetAlgorithm(),
			PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
			PublicKey: &kmspb.ChecksummedData{
				Data:           raw,
				Crc32CChecksum: wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(raw))),
			},
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		}, nil
	}
	if format != kmspb.PublicKey_PUBLIC_KEY_FORMAT_UNSPECIFIED && format != kmspb.PublicKey_PEM {
		return nil, status.Errorf(codes.InvalidArgument, "public_key_format %s is not valid for algorithm %s", format, v.pb.GetAlgorithm())
	}
	der, err := x509.MarshalPKIXPublicKey(v.signer.Public())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal public key: %v", err)
	}
	return &kmspb.PublicKey{
		Name:      req.GetName(),
		Pem:       string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Algorithm: v.pb.GetAlgorithm(),
	}, nil
}

func (s *fakeKMSServer) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("AsymmetricSign")
	v := s.versionLocked(req.GetName())
	if v == nil {
		return nil, status.Errorf(codes.NotFound, "crypto key version %q not found", req.GetName())
	}
	if v.pending > 0 || v.pb.GetState() != kmspb.CryptoKeyVersion_ENABLED {
		return nil, status.Errorf(codes.FailedPrecondition, "crypto key version %q is not enabled", req.GetName())
	}
	if _, externalMu, ok := mldsaAlgorithm(v.pb.GetAlgorithm()); ok {
		return signMLDSA(v, externalMu, req)
	}
	hash, pss, ok := algorithmScheme(v.pb.GetAlgorithm())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "algorithm %s does not sign digests", v.pb.GetAlgorithm())
	}
	var digest []byte
	var digestHash crypto.Hash
	switch d := req.GetDigest().GetDigest().(type) {
	case *kmspb.Digest_Sha256:
		digest, digestHash = d.Sha256, crypto.SHA256
	case *kmspb.Digest_Sha384:
		digest, digestHash = d.Sha384, crypto.SHA384
	case *kmspb.Digest_Sha512:
		digest, digestHash = d.Sha512, crypto.SHA512
	default:
		return nil, status.Error(codes.InvalidArgument, "digest is required")
	}
	if digestHash != hash {
		return nil, status.Errorf(codes.InvalidArgument, "digest %s does not match algorithm %s", digestHash, v.pb.GetAlgorithm())
	}
	if crc := req.GetDigestCrc32C(); crc != nil && crc.GetValue() != int64(gcpkmscrypto.Crc32c(digest)) {
		return nil, status.Error(codes.InvalidArgument, "digest checksum mismatch")
	}

	var sig []byte
	var err error
	switch key := v.signer.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		if pss {
			sig, err = rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: hash.Size()})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
		}
	default:
		err = status.Errorf(codes.Internal, "unexpected key type %T", v.signer)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &kmspb.AsymmetricSignResponse{
		Name:                 req.GetName(),
		Signature:            sig,
		SignatureCrc32C:      wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(sig))),
		VerifiedDigestCrc32C: req.GetDigestCrc32C() != nil,
		ProtectionLevel:      kmspb.ProtectionLevel_HSM,
	}, nil
}

// signMLDSA signs req.Data with an ML-DSA version the way KMS does: the
// data is the 64-byte μ for an EXTERNAL_MU algorithm and the message
// otherwise, a digest is not accepted, and the data checksum is verified.
func signMLDSA(v *fakeVersion, externalMu bool, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	key, ok := v.signer.(*mldsa.PrivateKey)
	if !ok {
		return nil, status.Errorf(codes.Internal, "unexpected key type %T", v.signer)
	}
	if req.GetDigest() != nil {
		return nil, status.Errorf(codes.InvalidArgument, "algorithm %s does not accept a digest", v.pb.GetAlgorithm())
	}
	data := req.GetData()
	if len(data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}
	if crc := req.GetDataCrc32C(); crc != nil && crc.GetValue() != int64(gcpkmscrypto.Crc32c(data)) {
		return nil, status.Error(codes.InvalidArgument, "data checksum mismatch")
	}
	var opts crypto.SignerOpts
	if externalMu {
		if len(data) != mldsaMuSize {
			return nil, status.Errorf(codes.InvalidArgument, "algorithm %s needs a %d-byte mu", v.pb.GetAlgorithm(), mldsaMuSize)
		}
		opts = crypto.MLDSAMu
	}
	sig, err := key.Sign(rand.Reader, data, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &kmspb.AsymmetricSignResponse{
		Name:               req.GetName(),
		Signature:          sig,
		SignatureCrc32C:    wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(sig))),
		VerifiedDataCrc32C: req.GetDataCrc32C() != nil,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}, nil
}

func (s *fakeKMSServer) DestroyCryptoKeyVersion(_ context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("DestroyCryptoKeyVersion")
	if err := s.destroyErrors[req.GetName()]; err != nil {
		return nil, err
	}
	v := s.versionLocked(req.GetName())
	if v == nil {
		return nil, status.Errorf(codes.NotFound, "crypto key version %q not found", req.GetName())
	}
	switch v.pb.GetState() {
	case kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_DISABLED:
	default:
		return nil, status.Errorf(codes.FailedPrecondition, "crypto key version %q is %s", req.GetName(), v.pb.GetState())
	}
	v.pb.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
	v.pb.DestroyTime = timestamppb.New(time.Now().Add(fakeDestroyWait))
	return proto.Clone(v.pb).(*kmspb.CryptoKeyVersion), nil
}

// startFakeKMS serves s on a loopback port and returns its address.
func startFakeKMS(t *testing.T, s *fakeKMSServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(server, s)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

// localClientOptions are the SDK options that reach a plaintext local
// server; the endpoint is passed separately, as Init does.
func localClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	}
}

// grpcClient returns a real SDK client for the fake server at addr.
func grpcClient(t *testing.T, addr string) gcpkmscrypto.KmsClient {
	t.Helper()
	client, err := gcpkmscrypto.NewKmsClient(context.Background(), addr, localClientOptions()...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// grpcProvider returns a provider for testKeyring whose real SDK client
// talks to s.
func grpcProvider(t *testing.T, s *fakeKMSServer) *gcpkmscrypto.Provider {
	t.Helper()
	client := grpcClient(t, startFakeKMS(t, s))
	return gcpkmscrypto.NewTestProvider(testTokenCfg(testKeyring), client, testKeyring)
}
