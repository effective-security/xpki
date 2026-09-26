package certutil

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

// IntermediateStash contains the path to the directory where
// downloaded intermediates should be saved.
// When unspecified, downloaded intermediates are not saved.
var IntermediateStash string

// HTTPClient is not read by this package.
//
// Deprecated: AIA downloads use the client passed to WithHTTPClient, or a
// client with a 3s timeout when none is given; setting this variable has no
// effect (XPKI-044).
var HTTPClient = http.DefaultClient

// ErrNoCertificates is returned, wrapped, when a Bundler or BuildBundle is
// given no certificate to bundle.
var ErrNoCertificates = errors.New("no certificates")

// BundleFlavor is named optimization strategy on certificate chain selection when bundling.
type BundleFlavor string

const (
	// Optimal means the shortest chain with newest intermediates and
	// the most advanced crypto.
	Optimal BundleFlavor = "optimal"

	// Force means the bundler only verifies the input as a valid bundle, not optimization is done.
	Force BundleFlavor = "force"
)

const (
	// defaultAIATimeout bounds one AIA request when the client has no Timeout.
	defaultAIATimeout = 3 * time.Second
	// maxAIAResponseSize bounds an AIA response body; larger responses are
	// rejected rather than truncated.
	maxAIAResponseSize = 1 << 20
)

const (
	expiringWarningStub  = "The bundle is expiring within 30 days."
	untrustedWarningStub = "The bundle may not be trusted by the following platform(s):"
	ubiquityWarning      = "Unable to measure bundle ubiquity: No platform metadata present."
)

// A Bundler contains the certificate pools for producing certificate
// bundles. It contains any intermediates and root certificates that
// should be used.
//
// A Bundler is safe for concurrent use. Intermediates learned over AIA are
// shared by later calls: they are published by replacing IntermediatePool
// and KnownIssuers with updated copies, so a pool or map once read is never
// modified (XPKI-035).
//
// The exported fields are set-up state. Set or replace them only before the
// first Bundle, ChainFromPEM or VerifyOptions call, and do not modify the
// pools or the map in place. After that, read the pools through
// VerifyOptions; reading the fields directly races with learning.
type Bundler struct {
	RootPool         *x509.CertPool
	IntermediatePool *x509.CertPool
	KnownIssuers     map[string]bool
	opts             options
	// mu guards the three exported fields once the Bundler is in use
	mu sync.RWMutex
}

type options struct {
	keyUsages   []x509.ExtKeyUsage
	withAIA     bool
	systemRoots bool
	client      *http.Client
	// flavor is empty unless WithBundleFlavor was given; NewBundler resolves it.
	flavor BundleFlavor
}

var defaultOptions = options{
	keyUsages: []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
	},
}

// An Option sets options such as allowed key usages, etc.
type Option func(*options)

// WithKeyUsages lets you set which Extended Key Usage values are acceptable. By
// default x509.ExtKeyUsageAny will be used.
func WithKeyUsages(usages ...x509.ExtKeyUsage) Option {
	return func(o *options) {
		o.keyUsages = usages
	}
}

// WithBundleFlavor selects Optimal or Force chain building. Without this
// option the flavor is Optimal when the Bundler has trust roots (explicit
// roots or WithSystemRoots) and Force otherwise. NewBundler rejects Optimal
// without trust roots and any other flavor value; the last option wins.
func WithBundleFlavor(flavor BundleFlavor) Option {
	return func(o *options) {
		o.flavor = flavor
	}
}

// WithAIA lets to enable downloading issuers from AIA.
func WithAIA(enable bool) Option {
	return func(o *options) {
		o.withAIA = enable
	}
}

// WithSystemRoots adds the platform trust store (x509.SystemCertPool) to the
// explicit roots. It is the only way a Bundler trusts system roots: without
// it, Optimal verification uses the explicit roots alone (XPKI-041).
func WithSystemRoots(enable bool) Option {
	return func(o *options) {
		o.systemRoots = enable
	}
}

// WithHTTPClient sets the client for AIA downloads. Each request is bounded
// by the client's Timeout, or 3s when it is zero, and by the context given
// to BundleContext. Only a 200 response of at most 1 MiB is parsed. Without
// this option a client with a 3s timeout is used.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) {
		o.client = client
	}
}

// LoadBundler creates a new Bundler from the files passed in; these
// files should contain a list of valid root certificates and a list
// of valid intermediate certificates, respectively.
func LoadBundler(rootBundleFile, intBundleFile string, opt ...Option) (*Bundler, error) {
	var caBundle, intBundle []byte
	var err error

	if rootBundleFile != "" {
		logger.KV(xlog.DEBUG, "status", "loading_root", "bundle", rootBundleFile)
		caBundle, err = os.ReadFile(rootBundleFile)
		if err != nil {
			return nil, errors.Wrapf(err, "root bundle failed to load")
		}
	}

	if intBundleFile != "" {
		logger.KV(xlog.DEBUG, "status", "loading_ca", "bundle", intBundleFile)
		intBundle, err = os.ReadFile(intBundleFile)
		if err != nil {
			return nil, errors.Wrapf(err, "intermediate CA bundle failed to load")
		}
	}

	if IntermediateStash != "" {
		if _, err = os.Stat(IntermediateStash); err != nil && os.IsNotExist(err) {
			logger.KV(xlog.DEBUG, "stash_folder", IntermediateStash)
			err = os.MkdirAll(IntermediateStash, 0755)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to create intermediate stash directory")
			}
		}
	}

	return NewBundlerFromPEM(caBundle, intBundle, opt...)
}

// NewBundlerFromPEM creates a new Bundler from PEM-encoded root certificates and
// intermediate certificates.
// Without root certificates the default flavor is Force; see NewBundler.
func NewBundlerFromPEM(rootBundlePEM, intBundlePEM []byte, opt ...Option) (*Bundler, error) {
	roots, err := ParseChainFromPEM(rootBundlePEM)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse root bundle")
	}

	intermediates, err := ParseChainFromPEM(intBundlePEM)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse intermediate bundle")
	}
	return NewBundler(roots, intermediates, opt...)
}

// NewBundler returns a Bundler that trusts roots, plus the system roots with
// WithSystemRoots, and uses intermediates to build chains. The flavor
// defaults to Optimal with trust roots and to Force without them; Optimal
// without trust roots is an error, so a Bundler never trusts system roots
// implicitly. RootPool is nil only when there are no trust roots.
func NewBundler(roots, intermediates []*x509.Certificate, opt ...Option) (*Bundler, error) {
	opts := defaultOptions
	for _, o := range opt {
		o(&opts)
	}

	hasRoots := len(roots) > 0 || opts.systemRoots
	switch opts.flavor {
	case "":
		opts.flavor = Force
		if hasRoots {
			opts.flavor = Optimal
		}
	case Force:
	case Optimal:
		if !hasRoots {
			return nil, errors.New("optimal bundle requires trust roots: provide roots or WithSystemRoots")
		}
	default:
		return nil, errors.Errorf("unsupported bundle flavor %q", opts.flavor)
	}

	b := &Bundler{
		KnownIssuers:     map[string]bool{},
		IntermediatePool: x509.NewCertPool(),
		opts:             opts,
	}

	if opts.systemRoots {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.WithMessage(err, "unable to load system roots")
		}
		b.RootPool = pool
	} else if len(roots) > 0 {
		b.RootPool = x509.NewCertPool()
	}

	for _, c := range roots {
		b.RootPool.AddCert(c)
		b.KnownIssuers[string(c.Signature)] = true
	}

	for _, c := range intermediates {
		b.IntermediatePool.AddCert(c)
		b.KnownIssuers[string(c.Signature)] = true
	}

	return b, nil
}

// VerifyOptions returns the x509.VerifyOptions used by Optimal bundling.
// Roots is never nil: without a RootPool it is an empty pool, so the options
// never fall back to the system roots.
// It is a snapshot: intermediates learned later are not added to it.
func (b *Bundler) VerifyOptions() x509.VerifyOptions {
	roots, intermediates, _ := b.snapshot()
	return b.verifyOptions(roots, intermediates)
}

// snapshot returns the current pools and known issuers. They are never
// modified afterwards; learn replaces them instead.
func (b *Bundler) snapshot() (roots, intermediates *x509.CertPool, known map[string]bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.RootPool, b.IntermediatePool, b.KnownIssuers
}

func (b *Bundler) verifyOptions(roots, intermediates *x509.CertPool) x509.VerifyOptions {
	if roots == nil {
		roots = x509.NewCertPool()
	}
	return x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     b.opts.keyUsages,
	}
}

// learn publishes verified intermediates for later calls. pool is a private
// pool built from base that already holds certs; it is installed as is when
// IntermediatePool is still base, and otherwise certs are added to a copy of
// the current pool. Certificates already known are skipped.
func (b *Bundler) learn(base, pool *x509.CertPool, certs []*x509.Certificate) {
	if len(certs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	known := make(map[string]bool, len(b.KnownIssuers)+len(certs))
	maps.Copy(known, b.KnownIssuers)
	current := b.IntermediatePool
	if current != base {
		pool = cloneCertPool(current)
		for _, c := range certs {
			if !known[string(c.Signature)] {
				pool.AddCert(c)
			}
		}
	}
	for _, c := range certs {
		known[string(c.Signature)] = true
	}
	b.IntermediatePool = pool
	b.KnownIssuers = known
}

// cloneCertPool returns a copy of pool, or an empty pool when it is nil.
func cloneCertPool(pool *x509.CertPool) *x509.CertPool {
	if pool == nil {
		return x509.NewCertPool()
	}
	return pool.Clone()
}

// ChainFromFile takes a set of files containing the PEM-encoded leaf certificate
// (optionally along with some intermediate certs), the PEM-encoded private key
// and returns the bundle built from that key and the certificate(s).
func (b *Bundler) ChainFromFile(bundleFile, keyFile string, password string) (*Chain, error) {
	certsRaw, err := os.ReadFile(bundleFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to load bundle")
	}

	var keyPEM []byte
	// Load private key PEM only if a file is given
	if keyFile != "" {
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to load private key")
		}
		if len(keyPEM) == 0 {
			return nil, errors.New("empty private key")
		}
	}

	return b.ChainFromPEM(certsRaw, keyPEM, password)
}

// ChainFromPEM builds a certificate chain from the set of byte
// slices containing the PEM or DER-encoded certificate(s), private key.
func (b *Bundler) ChainFromPEM(certsRaw, keyPEM []byte, password string) (*Chain, error) {
	return b.ChainFromPEMContext(context.Background(), certsRaw, keyPEM, password)
}

// ChainFromPEMContext is ChainFromPEM with a context that bounds and cancels
// AIA downloads; see BundleContext.
func (b *Bundler) ChainFromPEMContext(ctx context.Context, certsRaw, keyPEM []byte, password string) (*Chain, error) {
	var key crypto.Signer
	var err error
	if len(keyPEM) != 0 {
		var pwd []byte
		if password != "" {
			pwd = []byte(password)
		}
		key, err = ParsePrivateKeyPEMWithPassword(keyPEM, pwd)
		if err != nil {
			return nil, err
		}
	}

	certs, err := ParseChainFromPEM(certsRaw)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("failed to parse certificates")
	}

	return b.BundleContext(ctx, certs, key)
}

type fetchedIntermediate struct {
	Cert *x509.Certificate
	Name string
}

// fetchRemoteCertificate retrieves a single URL pointing to a certificate
// and attempts to first parse it as a DER-encoded certificate; if
// this fails, it attempts to decode it as a PEM-encoded certificate.
// The request is bounded by the client Timeout, or defaultAIATimeout when it
// is zero, and by ctx. Only a 200 response of at most maxAIAResponseSize is
// parsed; errors and logs never include the response body (XPKI-037).
func fetchRemoteCertificate(ctx context.Context, client *http.Client, certURL string) (*fetchedIntermediate, error) {
	logger.KV(xlog.DEBUG, "status", "fetching remote certificate", "url", certURL)

	ctx, cancel := context.WithTimeout(ctx, cmp.Or(client.Timeout, defaultAIATimeout))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid AIA URL %s", certURL)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch %s", certURL)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, certURL)
	}

	certData, err := io.ReadAll(io.LimitReader(resp.Body, maxAIAResponseSize+1))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read %s", certURL)
	}
	if len(certData) > maxAIAResponseSize {
		return nil, errors.Errorf("response from %s exceeds %d bytes", certURL, maxAIAResponseSize)
	}

	crt, err := x509.ParseCertificate(certData)
	if err != nil {
		crt, err = ParseFromPEM(certData)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse %d bytes from %s", len(certData), certURL)
		}
	}

	return &fetchedIntermediate{Cert: crt, Name: constructCertFileName(crt)}, nil
}

func httpClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = defaultAIATimeout
	}
	c := &http.Client{
		Timeout: timeout,
	}
	return c
}

func reverse(certs []*x509.Certificate) []*x509.Certificate {
	n := len(certs)
	if n == 0 {
		return certs
	}
	rcerts := []*x509.Certificate{}
	for i := n - 1; i >= 0; i-- {
		rcerts = append(rcerts, certs[i])
	}
	return rcerts
}

// Check if the certs form a partial cert chain: every cert verifies
// the signature of the one in front of it.
func partialVerify(certs []*x509.Certificate) bool {
	n := len(certs)
	if n == 0 {
		return false
	}
	for i := 0; i < n-1; i++ {
		if certs[i].CheckSignatureFrom(certs[i+1]) != nil {
			return false
		}
	}
	return true
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func isChainRootNode(cert *x509.Certificate) bool {
	return isSelfSigned(cert)
}

// verifyChain verifies the (partial) chain against the trust roots and
// publishes each verified intermediate with learn, including those verified
// before a later certificate fails. Each certificate is verified with the
// intermediates verified before it in this walk, which are kept in a private
// pool until learn publishes them.
func (b *Bundler) verifyChain(chain []*fetchedIntermediate) bool {
	roots, base, known := b.snapshot()
	pool := base
	var learned []*x509.Certificate
	learnedSigs := map[string]bool{}
	defer func() {
		b.learn(base, pool, learned)
	}()

	// This process will verify if the root of the (partial) chain is in our root pool,
	// and will fail otherwise.
	for vchain := chain[:]; len(vchain) > 0; vchain = vchain[1:] {
		cert := vchain[0]
		sig := string(cert.Cert.Signature)
		// If this is a certificate in one of the pools, skip it.
		if known[sig] || learnedSigs[sig] {
			continue
		}

		_, err := cert.Cert.Verify(b.verifyOptions(roots, pool))
		if err != nil {
			logger.KV(xlog.DEBUG, "status", "certificate failed verification", "err", err.Error())
			return false
		} else if len(chain) == len(vchain) && isChainRootNode(cert.Cert) {
			// The first certificate in the chain is a root; it shouldn't be stored.
			continue
		}

		// leaf cert has an empty name, don't store leaf cert.
		if cert.Name == "" {
			continue
		}

		if len(learned) == 0 {
			// the snapshot pool is shared; add to a private copy
			pool = cloneCertPool(base)
		}
		pool.AddCert(cert.Cert)
		learned = append(learned, cert.Cert)
		learnedSigs[sig] = true

		if IntermediateStash != "" {
			fileName := filepath.Join(IntermediateStash, cert.Name)

			var block = pem.Block{Type: "CERTIFICATE", Bytes: cert.Cert.Raw}

			logger.KV(xlog.DEBUG, "status", "write intermediate to stash directory", "fileName", fileName)
			// If the write fails, verification should not fail.
			err = os.WriteFile(fileName, pem.EncodeToMemory(&block), 0644)
			if err != nil {
				logger.KV(xlog.DEBUG, "reason", "failed to write new intermediate", "err", err.Error())
			} else {
				logger.KV(xlog.DEBUG, "status", "stashed new intermediate", "cert", cert.Name)
			}
		}
	}
	return true
}

// constructCertFileName returns a uniquely identifying file name for a certificate
func constructCertFileName(cert *x509.Certificate) string {
	// construct the filename as the CN with no period and space
	name := strings.ReplaceAll(cert.Subject.CommonName, ".", "")
	name = strings.ReplaceAll(name, " ", "")

	// add SKI and serial number as extra identifier
	name += fmt.Sprintf("_%x", cert.SubjectKeyId)
	name += fmt.Sprintf("_%x", cert.SerialNumber.Bytes())

	name += ".crt"
	return name
}

// fetchIntermediates goes through each of the URLs in the AIA "Issuing
// CA" extensions and fetches those certificates. If those
// certificates are not present in either the root pool or
// intermediate pool, the certificate is saved to file and added to
// the list of intermediates to be used for verification. This will
// not add any new certificates to the root pool; if the ultimate
// issuer is not trusted, fetching the certificate here will not change
// that. Each URL is requested at most once per call, whether it fails or
// not (XPKI-039); a later call retries it. It stops with the context error
// when ctx is done.
func (b *Bundler) fetchIntermediates(ctx context.Context, certs []*x509.Certificate) error {
	if IntermediateStash != "" {
		if _, err := os.Stat(IntermediateStash); err != nil && os.IsNotExist(err) {
			logger.KV(xlog.INFO, "reason", "creating intermediate stash directory", "folder", IntermediateStash)
			err = os.MkdirAll(IntermediateStash, 0755)
			if err != nil {
				logger.KV(xlog.ERROR, "reason", "failed to create intermediate stash directory", "folder", IntermediateStash, "err", err)
				return err
			}
		}
	}
	// AIA URLs requested and certificate signatures seen during this traversal
	seenURLs := map[string]bool{}
	seenCerts := map[string]bool{}
	var foundChains int

	// Construct a verify chain as a reversed partial bundle,
	// such that the certs are ordered by proximity to the root CAs.
	var chain []*fetchedIntermediate
	for i, cert := range certs {
		var name string

		// Only construct filenames for non-leaf intermediate certs
		// so they will be saved to disk if necessary.
		// Leaf cert gets a empty name and will be skipped.
		if i > 0 {
			name = constructCertFileName(cert)
		}

		chain = append([]*fetchedIntermediate{{cert, name}}, chain...)
		seenCerts[string(cert.Signature)] = true
	}

	client := b.opts.client
	if client == nil {
		client = httpClient(defaultAIATimeout)
	}

	// Verify the chain and store valid intermediates in the chain.
	// If it doesn't verify, fetch the intermediates and extend the chain
	// in a DFS manner and verify each time we hit a root.
	for {
		if len(chain) == 0 {
			if foundChains == 0 {
				return x509.UnknownAuthorityError{}
			}
			return nil
		}

		current := chain[0]
		var advanced bool
		if b.verifyChain(chain) {
			foundChains++
		}
		for _, url := range current.Cert.IssuingCertificateURL {
			if seenURLs[url] {
				continue
			}
			if !b.opts.withAIA {
				logger.KV(xlog.DEBUG, "reason", "AIA fetch disabled", "url", url)
				continue
			}

			// Mark before fetching, so a failing URL is not retried on backtrack.
			seenURLs[url] = true
			crt, err := fetchRemoteCertificate(ctx, client, url)
			if err != nil {
				logger.KV(xlog.DEBUG, "reason", "AIA fetch failed", "url", url, "err", err.Error())
				if ctxErr := ctx.Err(); ctxErr != nil {
					return errors.Wrapf(ctxErr, "AIA fetch of %s interrupted", url)
				}
				continue
			}

			sig := string(crt.Cert.Signature)
			if seenCerts[sig] {
				logger.KV(xlog.DEBUG, "status", "fetched certificate is known", "url", url)
				continue
			}
			seenCerts[sig] = true
			chain = append([]*fetchedIntermediate{crt}, chain...)
			advanced = true
			break
		}

		if !advanced {
			chain = chain[1:]
		}
	}
}

// Chain contains a certificate and its trust chain. It is intended
// to store the most widely applicable chain, with shortness an
// explicit goal.
type Chain struct {
	Chain       []*x509.Certificate
	Cert        *x509.Certificate
	Root        *x509.Certificate
	Key         any
	Issuer      *pkix.Name
	Subject     *pkix.Name
	Expires     time.Time
	LeafExpires time.Time
	Hostnames   []string
	Status      *BundleStatus
}

// buildHostnames sets bundle.Hostnames by the x509 cert's subject CN and DNS names
// Since the subject CN may overlap with one of the DNS names, it needs to handle
// the duplication by a set.
func (b *Chain) buildHostnames() {
	if b.Cert == nil {
		return
	}
	// hset keeps a set of unique hostnames.
	hset := make(map[string]bool)
	// insert CN into hset
	if b.Cert.Subject.CommonName != "" {
		hset[b.Cert.Subject.CommonName] = true
	}
	// insert all DNS names into hset
	for _, h := range b.Cert.DNSNames {
		hset[h] = true
	}

	// convert hset to an array of hostnames
	b.Hostnames = make([]string, len(hset))
	i := 0
	for h := range hset {
		b.Hostnames[i] = h
		i++
	}
}

// Bundle takes an X509 certificate (already in the
// Certificate structure), a private key as crypto.Signer in one of the appropriate
// formats (i.e. *rsa.PrivateKey or *ecdsa.PrivateKey, or even a opaque key), using them to
// build a certificate bundle. certs[0] is the leaf (a reversed chain is
// detected). A nil or empty certs returns an error matching
// ErrNoCertificates, and a nil entry returns an error (XPKI-036).
func (b *Bundler) Bundle(certs []*x509.Certificate, key crypto.Signer) (*Chain, error) {
	return b.BundleContext(context.Background(), certs, key)
}

// BundleContext is Bundle with a context that bounds and cancels AIA
// downloads. When ctx is done during an AIA download, the returned error
// matches ctx.Err() with errors.Is. An Optimal Bundler whose RootPool is nil
// fails instead of verifying against the system roots.
func (b *Bundler) BundleContext(ctx context.Context, certs []*x509.Certificate, key crypto.Signer) (*Chain, error) {
	if len(certs) == 0 {
		return nil, errors.WithStack(ErrNoCertificates)
	}
	for i, c := range certs {
		if c == nil {
			return nil, errors.Errorf("nil certificate at index %d", i)
		}
	}

	// Detect reverse ordering of the cert chain.
	if len(certs) > 1 && !partialVerify(certs) {
		rcerts := reverse(certs)
		if partialVerify(rcerts) {
			certs = rcerts
		}
	}

	var ok bool
	cert := certs[0]
	if key != nil {
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			var rsaPublicKey *rsa.PublicKey
			if rsaPublicKey, ok = key.Public().(*rsa.PublicKey); !ok {
				return nil, errors.New("key mismatch")
			}
			if !cert.PublicKey.(*rsa.PublicKey).Equal(rsaPublicKey) {
				return nil, errors.New("key mismatch")
			}
		case x509.ECDSA:
			var ecdsaPublicKey *ecdsa.PublicKey
			if ecdsaPublicKey, ok = key.Public().(*ecdsa.PublicKey); !ok {
				return nil, errors.New("key mismatch")
			}
			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(ecdsaPublicKey) {
				return nil, errors.New("key mismatch")
			}
		default:
			return nil, errors.New("unsupported key")
		}
	} else {
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
		case x509.ECDSA:
		default:
			return nil, errors.New("unsupported key")
		}
	}

	bundle := new(Chain)
	bundle.Cert = cert
	bundle.Key = key
	bundle.Issuer = &cert.Issuer
	bundle.Subject = &cert.Subject

	bundle.buildHostnames()

	if b.opts.flavor == Force {
		// force bundle checks the certificates
		// forms a verification chain.
		if !partialVerify(certs) {
			return nil, errors.New("unable to verify the certificate chain")
		}
		bundle.Chain = certs
	} else {
		roots, intermediates, _ := b.snapshot()
		// XPKI-041: x509.Verify with nil Roots would use the system roots.
		if roots == nil {
			return nil, errors.New("no trust roots configured")
		}
		// disallow self-signed cert
		if cert.CheckSignatureFrom(cert) == nil {
			return nil, errors.New("self-signed certificate")
		}

		chains, err := cert.Verify(b.verifyOptions(roots, intermediates))
		if err != nil {
			logger.KV(xlog.DEBUG, "reason", "verification failed", "err", err.Error())
			// If the error was an unknown authority, try to fetch
			// the intermediate specified in the AIA and add it to
			// the intermediates bundle.
			var unknownAuthority x509.UnknownAuthorityError
			if !errors.As(err, &unknownAuthority) {
				return nil, errors.WithMessage(err, "unable to verify the certificate chain")
			}

			searchErr := b.fetchIntermediates(ctx, certs)
			if searchErr != nil {
				logger.KV(xlog.DEBUG, "reason", "search failed", "err", searchErr.Error())
				if ctx.Err() != nil {
					return nil, errors.WithMessage(searchErr, "unable to verify the certificate chain")
				}
				return nil, errors.WithMessage(err, "unable to verify the certificate chain")
			}

			chains, err = cert.Verify(b.VerifyOptions())
			if err != nil {
				return nil, errors.Wrap(err, "unable to verify the certificate chain")
			}
		}
		matchingChains := optimalChains(chains)
		bundle.Chain = matchingChains[0]
	}

	statusCode := int(0)
	var messages []string
	// Check if bundle is expiring.
	expiringCerts := checkExpiringCerts(bundle.Chain)
	if len(expiringCerts) > 0 {
		statusCode |= BundleExpiringBit
		messages = append(messages, expirationWarning(expiringCerts))
	}

	// when forcing a bundle, bundle ubiquity doesn't matter
	// also we don't retrieve the anchoring root of the bundle
	if b.opts.flavor != Force {
		// Add root store presence info
		root := bundle.Chain[len(bundle.Chain)-1]
		bundle.Root = root
	}

	/*
		// Check if there is any platform that rejects the chain because of SHA1 deprecation.
		sha1Msgs := ubiquity.SHA1DeprecationMessages(bundle.Chain)
		if len(sha1Msgs) > 0 {
			statusCode |= BundleNotUbiquitousBit
			messages = append(messages, sha1Msgs...)
		}
	*/

	bundle.Status = &BundleStatus{
		ExpiringSKIs: getSKIs(bundle.Chain, expiringCerts),
		Code:         statusCode,
		Messages:     messages,
		Untrusted:    []string{},
	}

	// attempt to not to include the root certificate for optimization
	if b.opts.flavor != Force {
		// Include at least one intermediate if the leaf has enabled OCSP and is not CA.
		if bundle.Cert.OCSPServer != nil && !bundle.Cert.IsCA && len(bundle.Chain) <= 2 {
			// No op. Return one intermediate if there is one.
			logger.KV(xlog.DEBUG, "reason", "skipped_chain", "cert", bundle.Cert.Subject.CommonName)
		} else {
			// do not include the root.
			bundle.Chain = bundle.Chain[:len(bundle.Chain)-1]
		}
	}

	//bundle.Status.IsRebundled = diff(bundle.Chain, certs)
	bundle.Expires = ExpiryTime(bundle.Chain)
	bundle.LeafExpires = bundle.Chain[0].NotAfter

	return bundle, nil
}

// ExpiryTime returns the time when the certificate chain is expired.
func ExpiryTime(chain []*x509.Certificate) (notAfter time.Time) {
	if len(chain) == 0 {
		return
	}

	notAfter = chain[0].NotAfter
	for _, cert := range chain {
		if notAfter.After(cert.NotAfter) {
			notAfter = cert.NotAfter
		}
	}
	return
}

// Warning code for a success
const (
	BundleExpiringBit      int = 1 << iota // 0x01
	BundleNotUbiquitousBit                 // 0x02
)

// checkExpiringCerts returns indices of certs that are expiring within 30 days.
func checkExpiringCerts(chain []*x509.Certificate) (expiringIntermediates []int) {
	now := time.Now()
	for i, cert := range chain {
		if cert.NotAfter.Sub(now).Hours() < 720 {
			expiringIntermediates = append(expiringIntermediates, i)
		}
	}
	return
}

// getSKIs returns a list of cert subject key id  in the bundle chain with matched indices.
func getSKIs(chain []*x509.Certificate, indices []int) (skis []string) {
	for _, index := range indices {
		ski := fmt.Sprintf("%X", chain[index].SubjectKeyId)
		skis = append(skis, ski)
	}
	return
}

// expirationWarning generates a warning message with expiring certs.
func expirationWarning(expiringIntermediates []int) (ret string) {
	if len(expiringIntermediates) == 0 {
		return
	}

	ret = expiringWarningStub
	if len(expiringIntermediates) > 1 {
		ret = ret + "The expiring certs are"
	} else {
		ret = ret + "The expiring cert is"
	}
	for _, index := range expiringIntermediates {
		ret = ret + " #" + strconv.Itoa(index+1)
	}
	ret = ret + " in the chain."
	return
}

// Optimal chains are the shortest chains, with newest intermediates and most advanced crypto suite being the tie breaker.
func optimalChains(chains [][]*x509.Certificate) [][]*x509.Certificate {
	// Find shortest chains
	chains = filterChain(chains, compareChainLength)
	// Find the chains with longest expiry.
	chains = filterChain(chains, compareChainExpiry)
	return chains
}

// filterChain filters out the chains with highest rank according to the ranking function f.
func filterChain(chains [][]*x509.Certificate, f rankingFunc) [][]*x509.Certificate {
	// If there are no chain or only 1 chain, we are done.
	if len(chains) <= 1 {
		return chains
	}

	bestChain := chains[0]
	var candidateChains [][]*x509.Certificate
	for _, chain := range chains {
		r := f(bestChain, chain)
		if r < 0 {
			bestChain = chain
			candidateChains = [][]*x509.Certificate{chain}
		} else if r == 0 {
			candidateChains = append(candidateChains, chain)
		}
	}
	return candidateChains
}

// RankingFunc returns the relative rank between chain1 and chain2.
// Return value:
//
//	positive integer if rank(chain1) > rank(chain2),
//	negative integer if rank(chain1) < rank(chain2),
//	0 if rank(chain1) == (chain2).
type rankingFunc func(chain1, chain2 []*x509.Certificate) int

// CompareChainLength ranks shorter chain higher.
func compareChainLength(chain1, chain2 []*x509.Certificate) int {
	return len(chain2) - len(chain1)
}

func compareTime(t1, t2 time.Time) int {
	if t1.After(t2) {
		return 1
	} else if t1.Before(t2) {
		return -1
	}
	return 0
}

// CompareChainExpiry ranks chain that lasts longer higher.
func compareChainExpiry(chain1, chain2 []*x509.Certificate) int {
	t1 := ExpiryTime(chain1)
	t2 := ExpiryTime(chain2)
	return compareTime(t1, t2)
}
