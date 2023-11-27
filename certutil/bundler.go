package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

// IntermediateStash contains the path to the directory where
// downloaded intermediates should be saved.
// When unspecified, downloaded intermediates are not saved.
var IntermediateStash string

// HTTPClient is an instance of http.Client that will be used for all HTTP requests.
var HTTPClient = http.DefaultClient

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
	expiringWarningStub  = "The bundle is expiring within 30 days."
	untrustedWarningStub = "The bundle may not be trusted by the following platform(s):"
	ubiquityWarning      = "Unable to measure bundle ubiquity: No platform metadata present."
)

// A Bundler contains the certificate pools for producing certificate
// bundles. It contains any intermediates and root certificates that
// should be used.
type Bundler struct {
	RootPool         *x509.CertPool
	IntermediatePool *x509.CertPool
	KnownIssuers     map[string]bool
	opts             options
}

type options struct {
	keyUsages []x509.ExtKeyUsage
	withAIA   bool
	client    *http.Client
	flavor    BundleFlavor
}

var defaultOptions = options{
	keyUsages: []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
	},
	flavor: Optimal,
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

// WithBundleFlavor lets to specify bundle build Optimal or Force.
// Force is by default
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

// WithHTTPClient lets to specify http.Client for downloading AIA.
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
			logger.KV(xlog.DEBUG, "stach_folder", IntermediateStash)
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
// If caBundlePEM is nil, the resulting Bundler can only do "Force" bundle.
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

// NewBundler returns Bundler
func NewBundler(roots, intermediates []*x509.Certificate, opt ...Option) (*Bundler, error) {
	opts := defaultOptions

	if len(roots) == 0 {
		opts.flavor = Force
	}

	for _, o := range opt {
		o(&opts)
	}

	b := &Bundler{
		KnownIssuers:     map[string]bool{},
		IntermediatePool: x509.NewCertPool(),
		opts:             opts,
	}

	// RootPool will be nil if roots is empty
	if len(roots) > 0 {
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

// VerifyOptions generates an x509 VerifyOptions structure that can be
// used for verifying certificates.
func (b *Bundler) VerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         b.RootPool,
		Intermediates: b.IntermediatePool,
		KeyUsages:     b.opts.keyUsages,
	}
}

// ChainFromFile takes a set of files containing the PEM-encoded leaf certificate
// (optionally along with some intermediate certs), the PEM-encoded private key
// and returns the bundle built from that key and the certificate(s).
func (b *Bundler) ChainFromFile(bundleFile, keyFile string, password string) (*Chain, error) {
	certsRaw, err := ioutil.ReadFile(bundleFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to load bundle")
	}

	var keyPEM []byte
	// Load private key PEM only if a file is given
	if keyFile != "" {
		keyPEM, err = ioutil.ReadFile(keyFile)
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
	var key crypto.Signer
	var err error
	if len(keyPEM) != 0 {
		key, err = ParsePrivateKeyPEM(keyPEM)
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

	return b.Bundle(certs, key)
}

type fetchedIntermediate struct {
	Cert *x509.Certificate
	Name string
}

// fetchRemoteCertificate retrieves a single URL pointing to a certificate
// and attempts to first parse it as a DER-encoded certificate; if
// this fails, it attempts to decode it as a PEM-encoded certificate.
func fetchRemoteCertificate(client *http.Client, certURL string) (fi *fetchedIntermediate, err error) {
	logger.KV(xlog.DEBUG, "status", "fetching remote certificate", "url", certURL)
	var resp *http.Response
	resp, err = client.Get(certURL)
	if err != nil {
		logger.KV(xlog.DEBUG, "status", "failed HTTP get", "url", certURL, "err", err.Error())
		return
	}

	defer resp.Body.Close()
	var certData []byte
	certData, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.KV(xlog.DEBUG, "status", "failed read body", "url", certURL, "err", err.Error())
		return
	}

	crt, err := x509.ParseCertificate(certData)
	if err != nil {
		logger.KV(xlog.DEBUG, "status", "failed to parse certificate", "data", string(certData), "err", err.Error())

		crt, err = ParseFromPEM(certData)
		if err != nil {
			logger.KV(xlog.DEBUG, "status", "failed to parse certificate", "err", err.Error())
			return
		}
	}

	fi = &fetchedIntermediate{Cert: crt, Name: constructCertFileName(crt)}
	return
}

func httpClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 3 * time.Second
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

func (b *Bundler) verifyChain(chain []*fetchedIntermediate) bool {
	// This process will verify if the root of the (partial) chain is in our root pool,
	// and will fail otherwise.
	for vchain := chain[:]; len(vchain) > 0; vchain = vchain[1:] {
		cert := vchain[0]
		// If this is a certificate in one of the pools, skip it.
		if b.KnownIssuers[string(cert.Cert.Signature)] {
			continue
		}

		_, err := cert.Cert.Verify(b.VerifyOptions())
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

		b.IntermediatePool.AddCert(cert.Cert)
		b.KnownIssuers[string(cert.Cert.Signature)] = true

		if IntermediateStash != "" {
			fileName := filepath.Join(IntermediateStash, cert.Name)

			var block = pem.Block{Type: "CERTIFICATE", Bytes: cert.Cert.Raw}

			logger.KV(xlog.DEBUG, "status", "write intermediate to stash directory", "fileName", fileName)
			// If the write fails, verification should not fail.
			err = ioutil.WriteFile(fileName, pem.EncodeToMemory(&block), 0644)
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
	name := strings.Replace(cert.Subject.CommonName, ".", "", -1)
	name = strings.Replace(name, " ", "", -1)

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
// that.
func (b *Bundler) fetchIntermediates(certs []*x509.Certificate) (err error) {
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
	// stores URLs and certificate signatures that have been seen
	seen := map[string]bool{}
	var foundChains int

	// Construct a verify chain as a reversed partial bundle,
	// such that the certs are ordered by promxity to the root CAs.
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
		seen[string(cert.Signature)] = true
	}

	client := b.opts.client
	if client == nil {
		client = httpClient(time.Second * 3)
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
			if seen[url] {

				continue
			}
			var crt *fetchedIntermediate
			if b.opts.withAIA {
				crt, err = fetchRemoteCertificate(client, url)
				if err != nil {
					continue
				}

				if seen[string(crt.Cert.Signature)] {
					logger.KV(xlog.DEBUG, "status", "fetched certificate is known")
					continue
				}
				seen[url] = true
				seen[string(crt.Cert.Signature)] = true
				chain = append([]*fetchedIntermediate{crt}, chain...)
				advanced = true
				break
			} else {
				logger.KV(xlog.DEBUG, "reason", "AIA fetch disabled", "url", url)
			}
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
	Key         interface{}
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
// build a certificate bundle.
func (b *Bundler) Bundle(certs []*x509.Certificate, key crypto.Signer) (*Chain, error) {
	if len(certs) == 0 {
		return nil, nil
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
		switch {
		case cert.PublicKeyAlgorithm == x509.RSA:
			var rsaPublicKey *rsa.PublicKey
			if rsaPublicKey, ok = key.Public().(*rsa.PublicKey); !ok {
				return nil, errors.New("key mismatch")
			}
			if cert.PublicKey.(*rsa.PublicKey).N.Cmp(rsaPublicKey.N) != 0 {
				return nil, errors.New("key mismatch")
			}
		case cert.PublicKeyAlgorithm == x509.ECDSA:
			var ecdsaPublicKey *ecdsa.PublicKey
			if ecdsaPublicKey, ok = key.Public().(*ecdsa.PublicKey); !ok {
				return nil, errors.New("key mismatch")
			}
			if cert.PublicKey.(*ecdsa.PublicKey).X.Cmp(ecdsaPublicKey.X) != 0 {
				return nil, errors.New("key mismatch")
			}
		default:
			return nil, errors.New("unsupported key")
		}
	} else {
		switch {
		case cert.PublicKeyAlgorithm == x509.RSA:
		case cert.PublicKeyAlgorithm == x509.ECDSA:
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
		// disallow self-signed cert
		if cert.CheckSignatureFrom(cert) == nil {
			return nil, errors.New("self-signed certificate")
		}

		chains, err := cert.Verify(b.VerifyOptions())
		if err != nil {
			logger.KV(xlog.DEBUG, "reason", "verification failed", "err", err.Error())
			// If the error was an unknown authority, try to fetch
			// the intermediate specified in the AIA and add it to
			// the intermediates bundle.
			if _, ok := err.(x509.UnknownAuthorityError); !ok {
				return nil, errors.WithMessage(err, "unable to verify the certificate chain")
			}

			searchErr := b.fetchIntermediates(certs)
			if searchErr != nil {
				logger.KV(xlog.DEBUG, "reason", "search failed", "err", searchErr.Error())
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
