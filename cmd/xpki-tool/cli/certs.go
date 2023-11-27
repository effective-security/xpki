package cli

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

// CertsCmd provides certificates commands
type CertsCmd struct {
	Info     CertInfoCmd     `cmd:"" help:"print certificate info"`
	Validate CertValidateCmd `cmd:"" help:"validates certificate"`
}

// CertInfoCmd specifies flags for CertInfo action
type CertInfoCmd struct {
	In         string `kong:"arg" required:"" help:"certificate file name"`
	Out        string `help:"optional, output file to save parsed certificates"`
	NotAfter   string `help:"optional, filter certificates by NotAfter time"`
	NoExpired  *bool  `help:"optional, filter non-expired certificates"`
	Extensions bool   `help:"optional, print extensions values"`
}

// Run the command
func (a *CertInfoCmd) Run(ctx *Cli) error {
	// Load PEM
	pem, err := ctx.ReadFile(a.In)
	if err != nil {
		return errors.WithMessage(err, "unable to load PEM file")
	}

	list, err := certutil.ParseChainFromPEM(pem)
	if err != nil {
		return errors.WithMessage(err, "unable to parse PEM")
	}

	now := time.Now().UTC()
	if a.NoExpired != nil && *a.NoExpired {
		list = filterByNotAfter(list, now)
	}

	if a.NotAfter != "" {
		d, err := time.ParseDuration(a.NotAfter)
		if err != nil {
			return errors.WithMessage(err, "unable to parse --not-after")
		}
		list = filterByAfter(list, now.Add(d))
	}

	print.Certificates(ctx.Writer(), list, a.Extensions)

	if a.Out != "" {
		f, err := os.OpenFile(a.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return errors.WithMessage(err, "unable to create file")
		}
		defer f.Close()

		_ = certutil.EncodeToPEM(f, true, list...)
	}

	return nil
}

func filterByNotAfter(list []*x509.Certificate, notAfter time.Time) []*x509.Certificate {
	filtered := make([]*x509.Certificate, 0, len(list))
	for _, c := range list {
		if c.NotAfter.After(notAfter) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func filterByAfter(list []*x509.Certificate, notAfter time.Time) []*x509.Certificate {
	filtered := make([]*x509.Certificate, 0, len(list))
	for _, c := range list {
		if !c.NotAfter.After(notAfter) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// CertValidateCmd specifies flags for Validate action
type CertValidateCmd struct {
	Cert       string `kong:"arg" required:"" help:"certificate file name"`
	CA         string `help:"optional, CA bundle file"`
	Root       string `help:"optional, Trusted Roots file"`
	Out        string `help:"optional, output file to save certificate chain"`
	Revocation bool   `help:"optional, validate certificate revocation status"`
	Proxy      string `help:"optional, proxy address or DC name"`
	WithAIA    bool   `help:"optional, enable AIA to fetch intermediates"`
}

// Run the command
func (a *CertValidateCmd) Run(ctx *Cli) error {
	var err error
	var certBytes, cas []byte

	// set roots to empty
	roots := []byte("# empty Root bundle\n")

	certBytes, err = ctx.ReadFile(a.Cert)
	if err != nil {
		return errors.WithMessage(err, "unable to load cert")
	}

	if a.CA != "" {
		cas, err = ioutil.ReadFile(a.CA)
		if err != nil {
			return errors.WithMessage(err, "unable to load CA bundle")
		}
	}
	if a.Root != "" {
		roots, err = ioutil.ReadFile(a.Root)
		if err != nil {
			return errors.WithMessage(err, "unable to load Root bundle")
		}
	}

	timeout := time.Second * time.Duration(ctx.Timeout)
	client, err := httpClient(a.Proxy, timeout)
	if err != nil {
		return err
	}

	opts := []certutil.Option{
		certutil.WithHTTPClient(client),
		certutil.WithAIA(a.WithAIA),
	}

	w := ctx.Writer()
	bundle, bundleStatus, err := certutil.VerifyBundleFromPEM(certBytes, cas, roots, opts...)
	if err != nil {
		if crt, err2 := certutil.ParseFromPEM(certBytes); err2 == nil {
			print.Certificate(w, crt, false)
		}
		return errors.WithMessage(err, "unable to verify certificate")
	}

	if bundleStatus.IsUntrusted() {
		fmt.Fprintf(w, "ERROR: The cert is untrusted\n")
	}

	chain := bundle.Chain
	if bundle.RootCert != nil {
		chain = append(chain, bundle.RootCert)
	}

	print.Certificates(w, chain, false)

	if len(bundleStatus.ExpiringSKIs) > 0 {
		fmt.Fprintf(w, "\nWARNING: Expiring SKI:\n")
		for _, ski := range bundleStatus.ExpiringSKIs {
			fmt.Fprintf(w, "  -- %s\n", ski)
		}
	}
	if len(bundleStatus.Untrusted) > 0 {
		fmt.Fprintf(w, "\nWARNING: Untrusted SKI:\n")
		for _, ski := range bundleStatus.Untrusted {
			fmt.Fprintf(w, "  -- %s\n", ski)
		}
	}

	if a.Out != "" {
		pem := bundle.CertPEM + "\n" + bundle.CACertsPEM
		err = ioutil.WriteFile(a.Out, []byte(pem), 0664)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// revInfo stores all certificates statuses
	var revInfo []*certRevInfo

	// For Revocation Check
	if len(chain) > 0 && a.Revocation {
		var wg sync.WaitGroup

		for _, crt := range chain {
			if bytes.Equal(crt.RawIssuer, crt.RawSubject) {
				// skip root
				continue
			}

			issuer := certutil.FindIssuer(crt, chain, nil)
			if issuer == nil {
				continue
			}

			if len(crt.OCSPServer) == 0 {
				revInfo = append(revInfo, &certRevInfo{crt: crt, status: ocsp.Unknown, revokedType: "OCSP", err: errors.New("OCSP server is not present")})
				//				fmt.Fprintf(w, "OCSP server is not present: %s\n", crt.Subject.String())
			}

			for _, url := range crt.OCSPServer {
				wg.Add(1)
				go func(URL string) {
					defer wg.Done()

					status, _, err := OCSPValidation(client, crt, issuer, URL)
					if err != nil || status == ocsp.Revoked {
						revInfo = append(revInfo, &certRevInfo{crt: crt, status: status, err: err, url: URL, revokedType: "OCSP"})
					} else {
						revInfo = append(revInfo, &certRevInfo{crt: crt, status: status, url: URL, revokedType: "OCSP"})
					}
				}(url)
			}

			if len(crt.CRLDistributionPoints) == 0 {
				revInfo = append(revInfo, &certRevInfo{crt: crt, status: ocsp.Unknown, revokedType: "CRL", err: errors.New("CDP is not present")})
				//				fmt.Fprintf(w, "CRL endpoint is not present: %s\n", crt.Subject.String())
			}

			for _, url := range crt.CRLDistributionPoints {
				wg.Add(1)
				go func(URL string) {
					defer wg.Done()
					status, err := CRLValidation(client, crt, issuer, URL)
					if err != nil || status == ocsp.Revoked {
						revInfo = append(revInfo, &certRevInfo{crt: crt, status: status, err: err, url: URL, revokedType: "CRL"})
					} else {
						revInfo = append(revInfo, &certRevInfo{crt: crt, status: status, url: URL, revokedType: "CRL"})
					}
				}(url)
			}
			wg.Wait()
		}
	}

	// Prints all the certificate stores in revokedCerts
	if a.Revocation {

		aggrStatus := ocsp.Unknown
		fmt.Fprint(w, "\n============================= Revocation Info =============================\n")

		for _, crtInfo := range revInfo {
			if crtInfo.err != nil {
				fmt.Fprintf(w, "%s : ERROR: %s\n", crtInfo.crt.Subject.String(), crtInfo.err)
			} else {
				fmt.Fprintf(w, "%s: %s: %v\n", crtInfo.crt.Subject.String(), crtInfo.revokedType, statusMap[crtInfo.status])
				if crtInfo.status == ocsp.Revoked {
					aggrStatus = ocsp.Revoked
				}
			}
		}

		if aggrStatus == ocsp.Revoked {
			fmt.Fprintf(w, "\nCertificate chain is revoked\n")
		}
	}

	return nil
}

// OCSPValidation calls OCSP server and validate certificate
func OCSPValidation(client *http.Client, crt *x509.Certificate, issuer *x509.Certificate, rawURL string) (int, []byte, error) {
	logger.KV(xlog.DEBUG, "fetching", "ocsp", "url", rawURL)

	req, err := certutil.CreateOCSPRequest(crt, issuer, crypto.SHA256)
	if err != nil {
		return ocsp.Unknown, nil, err
	}

	der, err := postHTTP(client, rawURL, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return ocsp.Unknown, nil, err
	}

	res, err := ocsp.ParseResponseForCert(der, crt, issuer)
	if err != nil {
		logger.KV(xlog.DEBUG, "ocsp", string(der))
		return ocsp.Unknown, der, errors.WithMessagef(err, "failed to parse OCSP")
	}

	if res.NextUpdate.Before(time.Now()) {
		return ocsp.Unknown, der, errors.New("OCSP response is expired")
	}

	return res.Status, der, nil
}

// CRLValidation calls CRL Endpoint and check certificate in CRL
func CRLValidation(client *http.Client, crt *x509.Certificate, issuer *x509.Certificate, crlURL string) (int, error) {
	logger.KV(xlog.DEBUG, "fetching", "crl", "url", crlURL)

	der, err := download(client, crlURL)
	if err != nil {
		return ocsp.Unknown, errors.WithStack(err)
	}

	// ensure the CRL is valid
	certList, err := x509.ParseCRL(der)
	if err != nil {
		logger.KV(xlog.DEBUG, "crl", string(der))
		return ocsp.Unknown, errors.WithMessagef(err, "failed to parse CRL")
	}

	err = issuer.CheckCRLSignature(certList)
	if err != nil {
		return ocsp.Unknown, errors.WithMessage(err, "unable to verify CRL signature")
	}

	revokedList := (*certList).TBSCertList.RevokedCertificates
	for _, cert := range revokedList {
		if crt.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return ocsp.Revoked, nil
		}
	}
	return ocsp.Good, nil
}

// certRevInfo stores the information of revoked certificate
type certRevInfo struct {
	crt         *x509.Certificate
	status      int
	err         error
	url         string
	revokedType string
}

// statusMap maps status
var statusMap = map[int]string{
	ocsp.Good:    "good",
	ocsp.Revoked: "revoked",
	ocsp.Unknown: "unknown",
}

func httpClient(proxy string, timeout time.Duration) (*http.Client, error) {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	c := &http.Client{
		Timeout: timeout,
	}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, errors.Errorf("unable to parse proxy URL: %s", proxy)
		}
		c.Transport = &http.Transport{
			Proxy: http.ProxyURL(u),
		}
	}
	return c, nil
}

func postHTTP(client *http.Client, url string, contentType string, body io.Reader) ([]byte, error) {
	resp, err := client.Post(url, contentType, body)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to post to %s", url)
	}
	defer resp.Body.Close()

	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to download from %s", url)
	}

	return rbody, nil
}

func download(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to fetch from %s", url)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to download from %s", url)
	}

	return body, nil
}
