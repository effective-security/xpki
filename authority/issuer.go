package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/metricskey"
	"github.com/effective-security/xpki/oid"
)

// defaultBackdate applies when a profile does not set backdate.
const defaultBackdate = 5 * time.Minute

var (
	supportedKeyHash = []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}

	// allCSRFields is used when a profile has no allowed_fields.
	allCSRFields = csr.AllowedFields{
		Subject:        true,
		DNSNames:       true,
		IPAddresses:    true,
		EmailAddresses: true,
		URIs:           true,
	}

	// csrDeniedExtensions are derived from the profile or from the permitted
	// CSR fields and are never copied from a CSR, even when allow-listed
	// (XPKI-049). A trusted SignRequest may still supply them.
	csrDeniedExtensions = []asn1.ObjectIdentifier{
		oid.ExtensionSubjectKeyID,
		oid.ExtensionKeyUsage,
		oid.ExtensionSubjectAltName,
		oid.ExtensionBasicConstraints,
		oid.ExtensionAuthorityKeyID,
		oid.ExtensionExtendedKeyUsage,
		oid.OCSPNoCheck,
	}
)

// isCSRDeniedExtension reports whether a CSR may never supply the extension.
func isCSRDeniedExtension(id asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(csrDeniedExtensions, id.Equal)
}

// isIssuerGeneratedExtension reports whether the template fields already
// produce the extension, so an allow-listed CSR copy must not override it.
// Extensions generated as ExtraExtensions are found by OID instead.
func isIssuerGeneratedExtension(template *x509.Certificate, id asn1.ObjectIdentifier) bool {
	switch {
	case id.Equal(oid.ExtensionAuthorityInfoAccess):
		return len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0
	case id.Equal(oid.ExtensionCRLDistributionPoints):
		return len(template.CRLDistributionPoints) > 0
	}
	return false
}

// Issuer of certificates
type Issuer struct {
	cfg        IssuerConfig
	label      string
	skid       string // Subject Key ID
	signer     crypto.Signer
	sigAlgo    x509.SignatureAlgorithm
	bundle     *certutil.Bundle
	crlRenewal time.Duration
	crlExpiry  time.Duration
	ocspExpiry time.Duration
	crlURL     string
	aiaURL     string
	ocspURL    string

	// cabundlePEM contains PEM encoded certs for the issuer,
	// this bundle includes Issuing cert itself and its parents.
	cabundlePEM string

	keyHash  map[crypto.Hash][]byte
	nameHash map[crypto.Hash][]byte
	keyInfo  *certutil.KeyInfo

	// caResponder signs OCSP responses with the CA key; set once by CreateIssuer.
	caResponder *OCSPResponder
	// delegated is the current delegated OCSP responder (XPKI-052).
	delegated atomic.Pointer[OCSPResponder]
	// renewal is the outcome of the last delegated issuance attempt.
	renewal atomic.Pointer[ocspRenewal]
	// renewLock serializes delegated responder issuance.
	// Lock order: renewLock, then lock (XPKI-051).
	renewLock sync.Mutex
	// renewWaitHook, if set by tests, runs after a caller reads renewal and
	// before it waits for renewLock.
	renewWaitHook func()

	// lock guards cfg.Profiles.
	lock sync.RWMutex
}

// Bundle returns certificates bundle
func (ca *Issuer) Bundle() *certutil.Bundle {
	return ca.bundle
}

// PEM returns PEM encoded certs for the issuer
func (ca *Issuer) PEM() string {
	return ca.cabundlePEM
}

// CrlURL returns CRL DP URL
func (ca *Issuer) CrlURL() string {
	return ca.crlURL
}

// OcspURL returns OCSP URL
func (ca *Issuer) OcspURL() string {
	return ca.ocspURL
}

// AiaURL returns AIA URL
func (ca *Issuer) AiaURL() string {
	return ca.aiaURL
}

// Label returns label of the issuer
func (ca *Issuer) Label() string {
	return ca.label
}

// SubjectKID returns Subject Key ID
func (ca *Issuer) SubjectKID() string {
	return ca.skid
}

// Signer returns crypto.Signer
func (ca *Issuer) Signer() crypto.Signer {
	return ca.signer
}

// KeyHash returns key hash
func (ca *Issuer) KeyHash(h crypto.Hash) []byte {
	return ca.keyHash[h]
}

// NameHash returns name hash
func (ca *Issuer) NameHash(h crypto.Hash) []byte {
	return ca.nameHash[h]
}

// CrlRenewal is duration for CRL renewal interval
func (ca *Issuer) CrlRenewal() time.Duration {
	return ca.crlRenewal
}

// CrlExpiry is duration for CRL next update interval
func (ca *Issuer) CrlExpiry() time.Duration {
	return ca.crlExpiry
}

// OcspExpiry is duration for OCSP next update interval
func (ca *Issuer) OcspExpiry() time.Duration {
	return ca.ocspExpiry
}

// Profile returns CertProfile
func (ca *Issuer) Profile(name string) *CertProfile {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.cfg.Profiles[name]
}

// Profiles returns CertProfiles
func (ca *Issuer) Profiles() map[string]*CertProfile {
	ca.lock.RLock()
	defer ca.lock.RUnlock()
	return ca.cfg.Profiles
}

// AddProfile adds or replaces the CertProfile named label. Replacing the
// delegated_ocsp_profile takes effect at the next responder renewal, which
// fails if the new profile is not valid for delegation.
func (ca *Issuer) AddProfile(label string, p *CertProfile) {
	ca.lock.Lock()
	defer ca.lock.Unlock()
	ca.cfg.Profiles[label] = p
}

// NewIssuer creates Issuer from provided configuration
func NewIssuer(cfg *IssuerConfig, prov *cryptoprov.Crypto) (*Issuer, error) {
	return NewIssuerWithBundles(cfg, prov, nil, nil)
}

// NewIssuerWithBundles creates Issuer from provided configuration
func NewIssuerWithBundles(cfg *IssuerConfig, prov *cryptoprov.Crypto, caPem, rootPem []byte) (*Issuer, error) {
	// ensure that signer can be created before the key is generated
	cryptoSigner, err := prov.NewSignerFromFromFile(
		cfg.KeyFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to create signer")
	}

	// Build the bundle and register the CA cert
	var intCAbytes, rootBytes []byte
	if cfg.CABundleFile != "" {
		intCAbytes, err = os.ReadFile(cfg.CABundleFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load ca-bundle")
		}
	}
	intCAbytes = certutil.JoinPEM(intCAbytes, caPem)

	if cfg.RootBundleFile != "" {
		rootBytes, err = os.ReadFile(cfg.RootBundleFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load root-bundle")
		}
	}

	rootBytes = certutil.JoinPEM(rootBytes, rootPem)

	certBytes, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load cert")
	}
	issuer, err := CreateIssuer(cfg, certBytes, intCAbytes, rootBytes, cryptoSigner)
	if err != nil {
		return nil, err
	}
	_, err = issuer.CreateDelegatedOCSPSigner()
	if err != nil {
		return nil, errors.WithMessage(err, "unable to create delegated OCSP responder")
	}
	return issuer, nil
}

// CreateIssuer returns Issuer created directly from crypto.Signer,
// this method is mostly used for testing
func CreateIssuer(cfg *IssuerConfig, certBytes, intCAbytes, rootBytes []byte, signer crypto.Signer) (*Issuer, error) {
	cfg = cfg.Copy()
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*CertProfile)
	}

	keyInfo, err := certutil.NewKeyInfo(signer)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get key info")
	}

	label := cfg.Label
	bundle, status, err := certutil.VerifyBundleFromPEM(certBytes, intCAbytes, rootBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create signing CA cert bundle")
	}
	if status.IsUntrusted() {
		return nil, errors.Errorf("bundle is invalid: label=%s, cn=%q, expiresAt=%q, expiringSKU=[%v], untrusted=[%v]",
			label,
			bundle.Subject.CommonName,
			bundle.Expires.Format(time.RFC3339),
			strings.Join(status.ExpiringSKIs, ","),
			strings.Join(status.Untrusted, ","),
		)
	}

	var crlRenewal, crlExpiry, ocspExpiry time.Duration
	var crl, aia, ocsp string
	if cfg.AIA != nil {
		// NOTE: ${ISSUER_ID} was the old format, but has an issues in Helm
		// added another template as `:ISSUER_ID`

		crl = strings.ReplaceAll(cfg.AIA.CrlURL, "${ISSUER_ID}", bundle.SubjectID)
		crl = strings.ReplaceAll(crl, ":ISSUER_ID", bundle.SubjectID)

		aia = strings.ReplaceAll(cfg.AIA.AiaURL, "${ISSUER_ID}", bundle.SubjectID)
		aia = strings.ReplaceAll(aia, ":ISSUER_ID", bundle.SubjectID)

		ocsp = strings.ReplaceAll(cfg.AIA.OcspURL, "${ISSUER_ID}", bundle.SubjectID)
		ocsp = strings.ReplaceAll(ocsp, ":ISSUER_ID", bundle.SubjectID)

		crlRenewal = cfg.AIA.GetCRLRenewal()
		crlExpiry = cfg.AIA.GetCRLExpiry()
		ocspExpiry = cfg.AIA.GetOCSPExpiry()
		if name := cfg.AIA.DelegatedOCSPProfile; name != "" {
			if err := validateDelegatedOCSPProfile(cfg.Profiles[name], name, ocspExpiry); err != nil {
				return nil, errors.WithMessagef(err, "issuer %q", label)
			}
		}
	}

	keyHash := make(map[crypto.Hash][]byte)
	nameHash := make(map[crypto.Hash][]byte)

	for _, h := range supportedKeyHash {
		// OCSP requires Hash of the Key without Tag:
		/// issuerKeyHash is the hash of the issuer's public key.  The hash
		// shall be calculated over the value (excluding tag and length) of
		// the subject public key field in the issuer's certificate.
		var publicKeyInfo struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		_, err = asn1.Unmarshal(bundle.Cert.RawSubjectPublicKeyInfo, &publicKeyInfo)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode SubjectPublicKeyInfo")
		}

		keyHash[h] = certutil.Digest(h, publicKeyInfo.PublicKey.RightAlign())
		nameHash[h] = certutil.Digest(h, bundle.Cert.RawSubject)

		logger.KV(xlog.INFO,
			"label", label,
			"alg", certutil.HashAlgoToStr(h),
			"keyHash", hex.EncodeToString(keyHash[h]),
			"nameHash", hex.EncodeToString(nameHash[h]))
	}

	cabundlePEM := strings.TrimSpace(bundle.CertPEM)
	if bundle.CACertsPEM != "" {
		cabundlePEM = cabundlePEM + "\n" + strings.TrimSpace(bundle.CACertsPEM)
	}

	ca := &Issuer{
		cfg:         *cfg,
		skid:        certutil.GetSubjectKeyID(bundle.Cert),
		signer:      signer,
		sigAlgo:     csr.DefaultSigAlgo(signer),
		bundle:      bundle,
		label:       label,
		crlURL:      crl,
		aiaURL:      aia,
		ocspURL:     ocsp,
		cabundlePEM: cabundlePEM,
		keyHash:     keyHash,
		nameHash:    nameHash,
		crlRenewal:  crlRenewal,
		crlExpiry:   crlExpiry,
		ocspExpiry:  ocspExpiry,
		keyInfo:     keyInfo,
		caResponder: &OCSPResponder{
			Signer: signer,
			Cert:   bundle.Cert,
		},
	}
	logger.KV(xlog.NOTICE, "issuer", label, "skid", ca.skid, "crl_url", ca.crlURL, "ocsp_url", ca.ocspURL)
	return ca, nil
}

// SignProof returns base64 URL encoded signature of the data
func (ca *Issuer) SignProof(data []byte) (string, error) {
	defer metricskey.PerfCAOperation.MeasureSince(time.Now(), ca.label, "sign_proof")

	hasher := ca.keyInfo.Hash

	h := hasher.New()
	h.Write(data)
	sig, err := ca.signer.Sign(rand.Reader, h.Sum(nil), hasher)
	if err != nil {
		return "", errors.WithMessagef(err, "unable to sign proof")
	}

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyProof verifies the signature
func (ca *Issuer) VerifyProof(data []byte, proof string) error {
	hasher := ca.keyInfo.Hash

	signature, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return errors.Wrap(err, "unable to verify proof")
	}
	h := hasher.New()
	h.Write(data)

	if ca.keyInfo.Type == "RSA" {
		err = rsa.VerifyPKCS1v15(ca.signer.Public().(*rsa.PublicKey), hasher, h.Sum(nil), signature)
		if err != nil {
			return errors.Wrap(err, "invalid rsa signature")
		}
		return nil
	}

	ecc := ca.signer.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(ecc, h.Sum(nil), signature) {
		return errors.Errorf("ecdsa: invalid signature")
	}
	return nil
}

// Sign signs a new certificate based on the PEM-encoded
// certificate request with the specified profile.
func (ca *Issuer) Sign(raReq csr.SignRequest) (*x509.Certificate, []byte, error) {
	profileName := raReq.Profile
	if profileName == "" {
		profileName = "default"
	}
	profile := ca.Profile(profileName)
	if profile == nil {
		return nil, nil, errors.New("unsupported profile: " + profileName)
	}
	return ca.signWithProfile(raReq, profileName, profile)
}

// signWithProfile signs raReq with profile, a snapshot looked up by
// profileName, so that a caller can validate the exact profile it signs with.
func (ca *Issuer) signWithProfile(raReq csr.SignRequest, profileName string, profile *CertProfile) (*x509.Certificate, []byte, error) {
	defer metricskey.PerfCAOperation.MeasureSince(time.Now(), ca.label, "sign_cert")

	requesterCsrTemplate, err := csr.ParsePEM([]byte(raReq.Request))
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to parse CSR")
	}

	logger.KV(xlog.TRACE,
		"req", "cert",
		"profile", profileName,
		"csr_cn", requesterCsrTemplate.Subject.CommonName,
		"csr_ext", extensionsList(requesterCsrTemplate),
		"req_cn", raReq.SubjectCommonName(),
		"req_ext", raReq.ExtensionsIDs(),
	)

	// Copy out only the fields from the CSR authorized by policy (XPKI-049).
	// CSR extensions are never copied wholesale; see csrExtensions below.
	safeTemplate := x509.Certificate{
		PublicKeyAlgorithm: requesterCsrTemplate.PublicKeyAlgorithm,
		PublicKey:          requesterCsrTemplate.PublicKey,
		SignatureAlgorithm: ca.sigAlgo,
	}
	// If the profile contains no explicit allow-list, the subject and
	// SAN fields are copied from the CSR, still subject to the regexes.
	fields := profile.AllowedCSRFields
	if fields == nil {
		fields = &allCSRFields
	}
	if fields.Subject {
		safeTemplate.Subject = requesterCsrTemplate.Subject
	}
	if fields.DNSNames {
		safeTemplate.DNSNames = requesterCsrTemplate.DNSNames
	}
	if fields.IPAddresses {
		safeTemplate.IPAddresses = requesterCsrTemplate.IPAddresses
	}
	if fields.URIs {
		safeTemplate.URIs = requesterCsrTemplate.URIs
	}
	if fields.EmailAddresses {
		safeTemplate.EmailAddresses = requesterCsrTemplate.EmailAddresses
	}

	/*
		isSelfSign := ca.bundle == nil
			if safeTemplate.IsCA {
				if !profile.CAConstraint.IsCA {
					return nil, nil, errors.New("the policy disallows issuing CA certificate")
				}

				if !isSelfSign {
					caCert := ca.bundle.Cert
					if caCert.MaxPathLen > 0 {
						if safeTemplate.MaxPathLen >= caCert.MaxPathLen {
							return nil, nil, errors.New("the issuer disallows CA MaxPathLen extending")
						}
					} else if caCert.MaxPathLen == 0 && caCert.MaxPathLenZero {
						// signer has pathlen of 0, do not sign more intermediate CAs
						return nil, nil, errors.New("the issuer disallows issuing CA certificate")
					}
				}
			}
	*/

	safeTemplate.Subject = csr.PopulateName(raReq.Subject, safeTemplate.Subject)
	// allow Names to be signed
	safeTemplate.Subject.ExtraNames = safeTemplate.Subject.Names

	// If there is a whitelist, ensure that both the Common Name, SAN DNSNames and Emails match
	if profile.AllowedNamesRegex != nil && safeTemplate.Subject.CommonName != "" {
		if !profile.AllowedNamesRegex.Match([]byte(safeTemplate.Subject.CommonName)) {
			return nil, nil, errors.New("CommonName does not match allowed list: " + safeTemplate.Subject.CommonName)
		}
	}
	if profile.AllowedDNSRegex != nil {
		for _, name := range safeTemplate.DNSNames {
			if !profile.AllowedDNSRegex.Match([]byte(name)) {
				return nil, nil, errors.New("DNS Name does not match allowed list: " + name)
			}
		}
	}
	if profile.AllowedEmailRegex != nil {
		for _, name := range safeTemplate.EmailAddresses {
			if !profile.AllowedEmailRegex.Match([]byte(name)) {
				return nil, nil, errors.New("Email does not match allowed list: " + name)
			}
		}
	}
	if profile.AllowedURIRegex != nil {
		for _, u := range safeTemplate.URIs {
			uri := u.String()
			if !profile.AllowedURIRegex.Match([]byte(uri)) {
				return nil, nil, errors.New("URI does not match allowed list: " + uri)
			}
		}
	}

	{
		// RFC 5280 4.1.2.2:
		// Certificate users MUST be able to handle serialNumber
		// values up to 20 octets.  Conforming CAs MUST NOT use
		// serialNumber values longer than 20 octets.
		serialNumber := make([]byte, 20)
		_, err = io.ReadFull(rand.Reader, serialNumber)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to generate serial number")
		}

		// SetBytes interprets buf as the bytes of a big-endian
		// unsigned integer. The leading byte should be masked
		// off to ensure it isn't negative.
		serialNumber[0] &= 0x7F

		safeTemplate.SerialNumber = new(big.Int).SetBytes(serialNumber)
	}

	// One extension per OID (XPKI-050). Raw extensions are kept in the order
	// profile `extensions`, SignRequest, CSR; the first one for an OID wins.
	// fillTemplate then replaces any raw policies or OCSP no-check when the
	// profile sets them. Any other kept raw extension overrides the value
	// x509.CreateCertificate would build from template fields (KU, EKU,
	// basic constraints, SKI/AKI, SAN, AIA, CRL DP); the CSR cannot supply
	// those, except an AIA or CRL DP the issuer does not generate.
	for _, ext := range profile.Extensions {
		id := asn1.ObjectIdentifier(ext.ID)
		if certutil.FindExtension(safeTemplate.ExtraExtensions, id) != nil {
			return nil, nil, errors.Errorf("duplicate profile extension: %s", id.String())
		}
		raw, err := ext.GetValue()
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
			Id:       id,
			Critical: ext.Critical,
			Value:    raw,
		})
	}

	// The SignRequest comes from a trusted RA: an empty allow-list allows
	// every extension, including profile-owned OIDs.
	for _, ext := range raReq.Extensions {
		if !profile.IsAllowedExtention(ext.ID) {
			if ca.cfg.OmitDisabledExtensions {
				logger.KV(xlog.TRACE,
					"reason", "not_allowed",
					"profile", profileName,
					"ext", ext.ID.String(),
				)
				continue
			}
			return nil, nil, errors.Errorf("extension not allowed: %s", ext.ID.String())
		}
		id := asn1.ObjectIdentifier(ext.ID)
		if certutil.FindExtension(safeTemplate.ExtraExtensions, id) != nil {
			logger.KV(xlog.TRACE,
				"reason", "skipped_from_sign_request",
				"used", "profile_extension",
				"profile", profileName,
				"ext", id.String(),
			)
			continue
		}
		raw, err := ext.GetValue()
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
			Id:       id,
			Critical: ext.Critical,
			Value:    raw,
		})
	}

	// The CSR is untrusted (XPKI-049): profile-owned OIDs are always dropped,
	// and other extensions need an explicit allow-list entry. The accepted
	// ones are appended after fillTemplate so issuer-generated values win.
	var csrExtensions []pkix.Extension
	for _, ext := range requesterCsrTemplate.ExtraExtensions {
		if isCSRDeniedExtension(ext.Id) {
			logger.KV(xlog.TRACE,
				"reason", "profile_owned",
				"profile", profileName,
				"ext", ext.Id.String(),
			)
			continue
		}
		if !profile.allowsCSRExtension(ext.Id) {
			if ca.cfg.OmitDisabledExtensions {
				logger.KV(xlog.TRACE,
					"reason", "not_allowed",
					"profile", profileName,
					"ext", ext.Id.String(),
				)
				continue
			}
			return nil, nil, errors.Errorf("extension not allowed: %s", ext.Id.String())
		}
		csrExtensions = append(csrExtensions, ext)
	}
	csr.SetSAN(&safeTemplate, raReq.SAN)

	err = ca.fillTemplate(&safeTemplate, profile, raReq.NotBefore, raReq.NotAfter)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "failed to populate template")
	}

	for _, ext := range csrExtensions {
		if certutil.FindExtension(safeTemplate.ExtraExtensions, ext.Id) != nil ||
			isIssuerGeneratedExtension(&safeTemplate, ext.Id) {
			logger.KV(xlog.TRACE,
				"reason", "skipped_from_csr",
				"profile", profileName,
				"ext", ext.Id.String(),
			)
			continue
		}
		safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, ext)
	}

	var certTBS = safeTemplate

	signedCertPEM, err := ca.sign(&certTBS)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	//logger.KV(xlog.DEBUG, "signed", string(signedCertPEM))

	crt, err := certutil.ParseFromPEM(signedCertPEM)
	if err != nil {
		return nil, nil, err
	}

	// TODO: register issued cert

	return crt, signedCertPEM, nil
}

func (ca *Issuer) sign(template *x509.Certificate) ([]byte, error) {
	var caCert *x509.Certificate

	if ca.bundle == nil {
		// self-signed
		if !template.IsCA {
			return nil, errors.New("CA template is not specified")
		}
		template.DNSNames = nil
		template.EmailAddresses = nil
		template.URIs = nil
		caCert = template
	} else {
		caCert = ca.bundle.Cert
	}

	if template.NotAfter.After(caCert.NotAfter) {
		template.NotAfter = caCert.NotAfter
		if !template.NotBefore.Before(template.NotAfter) {
			return nil, errors.Errorf("certificate NotBefore %s is not before issuer NotAfter %s",
				template.NotBefore.UTC().Format(time.RFC3339),
				caCert.NotAfter.UTC().Format(time.RFC3339))
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, template.PublicKey, ca.signer)
	if err != nil {
		return nil, errors.Wrap(err, "create certificate")
	}

	uris := make([]string, 0, len(template.URIs))
	for _, uri := range template.URIs {
		uris = append(uris, uri.String())
	}

	logger.KV(xlog.NOTICE,
		"signed", "cert",
		"serial", template.SerialNumber,
		"CN", template.Subject.CommonName,
		"URI", uris,
		"DNS", template.DNSNames,
		"Email", template.EmailAddresses,
		"extensions", extensionsList(template),
	)

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return cert, nil
}

func extensionsList(crt *x509.Certificate) []string {
	var list []string
	for _, ex := range crt.Extensions {
		list = append(list, ex.Id.String())
	}
	return list
}

func (ca *Issuer) fillTemplate(template *x509.Certificate, profile *CertProfile, notBefore, notAfter time.Time) error {
	ski, err := computeSKI(template)
	if err != nil {
		return err
	}

	/* for debugging
	js, _ := json.Marshal(profile)
	fmt.Printf("fillTemplate: %v, notBefore=%v, notAfter=%v", string(js),
		notBefore.Format(time.RFC3339),
		notAfter.Format(time.RFC3339))
	*/

	var (
		eku []x509.ExtKeyUsage
		ku  x509.KeyUsage

		isOCSPResponder = false
	)

	notBefore, notAfter, err = validityWindow(profile, time.Now(), notBefore, notAfter)
	if err != nil {
		return err
	}

	// The third value returned from Usages is a list of unknown key usages.
	// This should be used when validating the profile at load, and isn't used
	// here.
	ku, eku, _ = profile.Usages()
	if ku == 0 && len(eku) == 0 && profile.FindExtension(oid.ExtensionKeyUsage) == nil {
		return errors.Errorf("invalid profile: no key usages")
	}

	template.NotBefore = notBefore
	template.NotAfter = notAfter
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	template.IsCA = profile.CAConstraint.IsCA
	if template.IsCA {
		logger.KV(xlog.NOTICE, "subject", template.Subject.String(), "is_ca", "true", "MaxPathLen", profile.CAConstraint.MaxPathLen)
		template.BasicConstraintsValid = true
		template.MaxPathLen = profile.CAConstraint.MaxPathLen
		template.MaxPathLenZero = template.MaxPathLen == 0
		template.DNSNames = nil
		template.IPAddresses = nil
		template.EmailAddresses = nil
		template.URIs = nil
	} else {
		template.BasicConstraintsValid = true
		template.MaxPathLen = -1

		// Do not include OCSP and CDP to delegated OCSP responder cert
		isSigner, err := isOCSPSigningTemplate(template)
		if err != nil {
			return err
		}
		isOCSPResponder = isSigner &&
			(profile.OCSPNoCheck || certutil.HasOCSPNoCheck(template))
	}
	template.SubjectKeyId = ski

	ocspURL := ca.OcspURL()
	if !isOCSPResponder && ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	crlURL := ca.CrlURL()
	if !isOCSPResponder && crlURL != "" {
		template.CRLDistributionPoints = []string{crlURL}
	}
	issuerURL := ca.AiaURL()
	if issuerURL != "" {
		template.IssuingCertificateURL = []string{issuerURL}
	}
	if len(profile.Policies) != 0 {
		err = addPolicies(template, profile.Policies, profile.PoliciesCritical)
		if err != nil {
			return errors.WithMessagef(err, "invalid profile policies")
		}
	}
	if profile.OCSPNoCheck {
		ocspNoCheckExtension := pkix.Extension{
			Id:       oid.OCSPNoCheck,
			Critical: false,
			Value:    []byte{0x05, 0x00},
		}
		// the profile value replaces one supplied by the request (XPKI-050)
		template.ExtraExtensions = setExtension(template.ExtraExtensions, ocspNoCheckExtension)
	}

	return nil
}

// effectiveBackdate is the profile backdate, or defaultBackdate if unset.
func effectiveBackdate(profile *CertProfile) time.Duration {
	if backdate := profile.Backdate.TimeDuration(); backdate != 0 {
		return backdate
	}
	return defaultBackdate
}

// validityWindow returns the certificate validity for the requested times
// (XPKI-054). Zero times take the profile defaults: NotBefore is now rounded
// to a minute minus backdate (default 5m), NotAfter is NotBefore plus expiry.
// Explicit times must fall in the profile envelope: NotBefore no earlier than
// now minus backdate, NotAfter after NotBefore, and a lifetime no longer
// than the profile expiry. A profile without expiry needs an explicit
// NotAfter and has no lifetime bound; LoadConfig rejects such profiles.
func validityWindow(profile *CertProfile, now, notBefore, notAfter time.Time) (time.Time, time.Time, error) {
	expiry := profile.Expiry.TimeDuration()
	if expiry == 0 && notAfter.IsZero() {
		return time.Time{}, time.Time{}, errors.New("expiry is not set")
	}

	backdate := effectiveBackdate(profile)
	if notBefore.IsZero() {
		notBefore = now.Round(time.Minute).Add(-backdate)
	} else if earliest := now.Truncate(time.Minute).Add(-backdate); notBefore.Before(earliest) {
		return time.Time{}, time.Time{}, errors.Errorf("NotBefore %s is earlier than allowed %s",
			notBefore.UTC().Format(time.RFC3339),
			earliest.UTC().Format(time.RFC3339))
	}
	if notAfter.IsZero() {
		notAfter = notBefore.Add(expiry)
	}

	if !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, errors.Errorf("invalid validity: NotAfter %s is not after NotBefore %s",
			notAfter.UTC().Format(time.RFC3339),
			notBefore.UTC().Format(time.RFC3339))
	}
	if lifetime := notAfter.Sub(notBefore); expiry > 0 && lifetime > expiry {
		return time.Time{}, time.Time{}, errors.Errorf("validity %s exceeds profile expiry %s", lifetime, expiry)
	}
	return notBefore.UTC(), notAfter.UTC(), nil
}
