package cli

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/x/ctl"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// CsrCmd is the parent for CSR command
type CsrCmd struct {
	Create  CsrCreateCmd `cmd:"" help:"create certificate request"`
	GenCert GenCertCmd   `cmd:"" help:"create CSR and sign certificate"`
	Sign    CsrSignCmd   `cmd:"" help:"sign certificate"`
}

// CsrCreateCmd specifies flags for Create command
type CsrCreateCmd struct {
	CsrProfile string `required:"" help:"file name with CSR profile"`
	KeyLabel   string `required:"" help:"name for generated key"`
	Output     string `help:"the optional prefix for output files; if not set, the output will be printed to STDOUT only"`
}

// Run the command
func (a *CsrCreateCmd) Run(ctx *Cli) error {
	cryptoprov, defaultCrypto := ctx.CryptoProv()
	if cryptoprov == nil {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	prov := csr.NewProvider(defaultCrypto)

	csrf, err := ctx.ReadFile(a.CsrProfile)
	if err != nil {
		return errors.WithMessage(err, "read CSR profile")
	}

	req := csr.CertificateRequest{
		KeyRequest: prov.NewKeyRequest(prefixKeyLabel(a.KeyLabel), "ECDSA", 256, csr.SigningKey),
	}

	if strings.HasSuffix(a.CsrProfile, "json") {
		err = json.Unmarshal(csrf, &req)
	} else {
		err = yaml.Unmarshal(csrf, &req)
	}
	if err != nil {
		return errors.WithMessage(err, "invalid CSR")
	}

	var key, csrPEM []byte
	csrPEM, key, _, _, err = prov.CreateRequestAndExportKey(&req)
	if err != nil {
		return errors.WithMessage(err, "process CSR")
	}

	if a.Output == "" {
		ctl.WriteCert(ctx.Writer(), key, csrPEM, nil)
	} else {
		err = saveCert(a.Output, key, csrPEM, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// GenCertCmd specifies flags for GenCert command
type GenCertCmd struct {
	SelfSign   bool     `help:"generate self-signed cert"`
	CACert     string   `help:"file name of the signing CA cert"`
	CAKey      string   `help:"file name of the signing CA key"`
	CAConfig   string   `required:"" help:"file name with ca-config"`
	CsrProfile string   `required:"" help:"file name with CSR profile"`
	Profile    string   `required:"" help:"certificate profile name from CA config"`
	KeyLabel   string   `required:"" help:"name for generated key"`
	San        []string `help:"Subject Alt Names for generated cert"`

	PemInfo bool   `help:"Include certificate info in PEM file"`
	Output  string `help:"the optional prefix for output files; if not set, the output will be printed to STDOUT only"`
}

// Run the command
func (a *GenCertCmd) Run(ctx *Cli) error {
	cryptoprov, defaultCrypto := ctx.CryptoProv()
	if cryptoprov == nil {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	isscfg := &authority.IssuerConfig{}

	if a.SelfSign {
		if a.CAKey != "" {
			return errors.Errorf("--self-sign can not be used with --ca-key")
		}
	} else {
		if a.CAKey == "" || a.CACert == "" {
			return errors.Errorf("CA certificate and key are required")
		}
		isscfg.CertFile = a.CACert
		isscfg.KeyFile = a.CAKey
	}

	// Load CSR
	csrf, err := ctx.ReadFile(a.CsrProfile)
	if err != nil {
		return errors.WithMessage(err, "read CSR profile")
	}

	prov := csr.NewProvider(defaultCrypto)
	req := csr.CertificateRequest{
		KeyRequest: prov.NewKeyRequest(prefixKeyLabel(a.KeyLabel), "ECDSA", 256, csr.SigningKey),
	}

	if strings.HasSuffix(a.CsrProfile, "json") {
		err = json.Unmarshal(csrf, &req)
	} else {
		err = yaml.Unmarshal(csrf, &req)
	}
	if err != nil {
		return errors.WithMessage(err, "invalid CSR profile")
	}

	if len(a.San) > 0 {
		req.SAN = a.San
	}

	// Load ca-config
	cacfg, err := authority.LoadConfig(a.CAConfig)
	if err != nil {
		return errors.WithMessage(err, "ca-config")
	}
	err = cacfg.Validate()
	if err != nil {
		return errors.WithMessage(err, "invalid ca-config")
	}

	isscfg.Profiles = cacfg.Profiles

	var key, csrPEM, certPEM []byte

	if a.SelfSign {
		certPEM, csrPEM, key, err = authority.NewRoot(a.Profile,
			cacfg,
			defaultCrypto, &req)
		if err != nil {
			return err
		}

		crt, _ := certutil.ParseFromPEM(certPEM)
		pem, _ := certutil.EncodeToPEMString(a.PemInfo, crt)
		certPEM = []byte(pem + "\n")
	} else {
		issuer, err := authority.NewIssuer(isscfg, cryptoprov)
		if err != nil {
			return errors.WithMessage(err, "create issuer")
		}

		csrPEM, key, _, _, err = prov.CreateRequestAndExportKey(&req)
		if err != nil {
			return errors.WithMessage(err, "process CSR")
		}

		signReq := csr.SignRequest{
			Request: string(csrPEM),
			Profile: a.Profile,
		}

		crt, _, err := issuer.Sign(signReq)
		if err != nil {
			return errors.WithMessage(err, "sign request")
		}

		pem, _ := certutil.EncodeToPEMString(a.PemInfo, crt)
		certPEM = []byte(pem + "\n")
	}

	if a.Output == "" {
		ctl.WriteCert(ctx.Writer(), key, csrPEM, certPEM)
	} else {
		err = saveCert(a.Output, key, csrPEM, certPEM)
		if err != nil {
			return errors.WithMessagef(err, "unable to save generated files")
		}
	}

	return nil
}

// CsrSignCmd signs certificate request
type CsrSignCmd struct {
	Csr      string   `kong:"arg" required:"" help:"file name with pem-encoded CSR to sign"`
	CACert   string   `required:"" help:"file name of the signing CA cert"`
	CAKey    string   `required:"" help:"file name of the signing CA key"`
	CAConfig string   `required:"" help:"file name with ca-config"`
	Profile  string   `required:"" help:"certificate profile name from CA config"`
	San      []string `help:"Subject Alt Names for generated cert"`

	AiaURL  string `help:"optional AIA to add to the certificate"`
	OcspURL string `help:"optional OCSP URL to add to the certificate"`
	CrlURL  string `help:"optional CRL DP to add to the certificate"`

	PemInfo bool   `help:"Include certificate info in PEM file"`
	Output  string `help:"the optional prefix for output files; if not set, the output will be printed to STDOUT only"`
}

// Run the command
func (a *CsrSignCmd) Run(ctx *Cli) error {
	cryptoprov, _ := ctx.CryptoProv()
	if cryptoprov == nil {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	// Load CSR
	csrPEM, err := ctx.ReadFile(a.Csr)
	if err != nil {
		return errors.WithMessage(err, "read CSR")
	}

	// Load ca-config
	cacfg, err := authority.LoadConfig(a.CAConfig)
	if err != nil {
		return errors.WithMessage(err, "failed to load CA configuration")
	}
	err = cacfg.Validate()
	if err != nil {
		return errors.WithMessage(err, "invalid ca-config")
	}

	isscfg := &authority.IssuerConfig{
		CertFile: a.CACert,
		KeyFile:  a.CAKey,
		AIA: &authority.AIAConfig{
			AiaURL:  a.AiaURL,
			OcspURL: a.OcspURL,
			CrlURL:  a.CrlURL,
		},
		Profiles: cacfg.Profiles,
	}

	issuer, err := authority.NewIssuer(isscfg, cryptoprov)
	if err != nil {
		return errors.WithMessage(err, "create issuer")
	}

	signReq := csr.SignRequest{
		SAN:     a.San,
		Request: string(csrPEM),
		Profile: a.Profile,
	}

	crt, _, err := issuer.Sign(signReq)
	if err != nil {
		return errors.WithMessage(err, "sign request")
	}
	pem, _ := certutil.EncodeToPEMString(a.PemInfo, crt)

	if a.Output == "" {
		ctl.WriteCert(ctx.Writer(), nil, nil, []byte(pem+"\n"))
	} else {
		err = saveCert(a.Output, nil, nil, []byte(pem+"\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

// SaveCert to file
func saveCert(baseName string, key, csrPEM, certPEM []byte) error {
	var err error
	if len(certPEM) > 0 {
		err = os.WriteFile(baseName+".pem", certPEM, 0664)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	if len(csrPEM) > 0 {
		err = os.WriteFile(baseName+".csr", csrPEM, 0664)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	if len(key) > 0 {
		err = os.WriteFile(baseName+".key", key, 0600)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
