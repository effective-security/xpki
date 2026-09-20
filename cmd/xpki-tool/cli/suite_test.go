package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite
	tmpdir string
	ctl    *Cli
	// Out is the output buffer
	Out bytes.Buffer

	appFlags []string
}

func (s *testSuite) SetupSuite() {
	s.tmpdir = filepath.Join(os.TempDir(), "/tests/xpki", "xpki-tool")
	err := os.MkdirAll(s.tmpdir, 0777)
	s.Require().NoError(err)

	s.ctl = &Cli{}

	s.ctl.WithErrWriter(&s.Out).
		WithWriter(&s.Out)

	parser, err := kong.New(s.ctl,
		kong.Name("xpki-tool"),
		kong.Description("CLI tool"),
		kong.Writers(&s.Out, &s.Out),
		ctl.BoolPtrMapper,
		//kong.Exit(exit),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{})
	if err != nil {
		s.FailNow("unexpected error constructing Kong: %+v", err)
	}

	flags := s.appFlags
	_, err = parser.Parse(flags)
	if err != nil {
		s.FailNow("unexpected error parsing: %+v", err)
	}
}

func (s *testSuite) TearDownSuite() {
	_ = os.RemoveAll(s.tmpdir)
}

// HasText is a helper method to assert that the out stream contains the supplied
// text somewhere
func (s *testSuite) HasText(texts ...string) {
	outStr := s.Out.String()
	for _, t := range texts {
		s.Contains(outStr, t)
	}
}

// HasNoText is a helper method to assert that the out stream does contains the supplied
// text somewhere
func (s *testSuite) HasNoText(texts ...string) {
	outStr := s.Out.String()
	for _, t := range texts {
		s.NotContains(outStr, t)
	}
}

// HasTextInFile is a helper method to assert that file contains the supplied text
func (s *testSuite) HasTextInFile(file string, texts ...string) {
	f, err := os.ReadFile(file)
	s.Require().NoError(err, "unable to read: %s", file)
	outStr := string(f)
	for _, t := range texts {
		s.Contains(outStr, t, "expecting to find text %q in file %q", t, file)
	}
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(testSuite))
}

func (s *testSuite) TestCrsInfo() {
	cmd := CsrInfoCmd{
		Csr: "../../../x/print/testdata/trusty_dev_peer.csr",
	}
	err := cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.HasText()
}

func (s *testSuite) TestOcspInfo() {
	cmd := OCSPInfoCmd{
		In: "testdata/ocsp1.res",
	}
	err := cmd.Run(s.ctl)
	s.NoError(err)
}

func (s *testSuite) TestCertInfo() {
	cmd := CertInfoCmd{
		In: "../../../x/print/testdata/trusty_peer_wfe.pem",
	}
	err := cmd.Run(s.ctl)
	s.NoError(err)
}

func (s *testSuite) TestCertValidate() {
	cmd := CertValidateCmd{
		Cert: "../../../x/print/testdata/trusty_peer_wfe.pem",
	}
	// expired chain from a private CA: with no --root the system trust store is
	// used, so the chain must be rejected rather than accepted in Force mode
	err := cmd.Run(s.ctl)
	s.Error(err)
	s.Contains(err.Error(), "unable to verify certificate")
}

func (s *testSuite) TestCertValidateWithRoot() {
	root := testca.NewEntity(testca.Authority)
	leaf := testca.NewEntity(testca.Issuer(root), testca.DNSName("localhost"))

	rootPEM, err := certutil.EncodeToPEMString(false, root.Certificate)
	s.Require().NoError(err)
	leafPEM, err := certutil.EncodeToPEMString(false, leaf.Certificate)
	s.Require().NoError(err)

	rootFile := filepath.Join(s.tmpdir, "validate_root.pem")
	leafFile := filepath.Join(s.tmpdir, "validate_leaf.pem")
	s.Require().NoError(os.WriteFile(rootFile, []byte(rootPEM), 0600))
	s.Require().NoError(os.WriteFile(leafFile, []byte(leafPEM), 0600))

	s.Out.Reset()
	cmd := CertValidateCmd{
		Cert: leafFile,
		Root: rootFile,
	}
	s.Require().NoError(cmd.Run(s.ctl))
	s.HasText("localhost")
	s.HasNoText("untrusted")

	// the same leaf without the private root is not anchored anywhere
	cmd = CertValidateCmd{Cert: leafFile}
	err = cmd.Run(s.ctl)
	s.Error(err)
}
