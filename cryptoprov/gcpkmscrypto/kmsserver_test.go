package gcpkmscrypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
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

func (s *fakeKMSServer) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("ListCryptoKeys")
	resp := &kmspb.ListCryptoKeysResponse{}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range s.keys {
			if !yield(name) {
				return
			}
		}
	}) {
		if strings.HasPrefix(name, req.GetParent()+cryptoKeysPath) {
			resp.CryptoKeys = append(resp.CryptoKeys, proto.Clone(s.keys[name]).(*kmspb.CryptoKey))
		}
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
