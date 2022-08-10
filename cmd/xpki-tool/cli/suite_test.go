package cli

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/effective-security/xpki/x/ctl"
	"github.com/effective-security/xpki/x/fileutil"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite
	tmpdir string
	ctl    *Cli
	// Out is the outpub buffer
	Out bytes.Buffer

	appFlags []string
}

func (s *testSuite) SetupSuite() {
	s.tmpdir = filepath.Join(os.TempDir(), "/tests/xpki", "xpki-tool")
	err := fileutil.Vfs.MkdirAll(s.tmpdir, 0777)
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
	fileutil.Vfs.RemoveAll(s.tmpdir)
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
		s.Contains(outStr, t)
	}
}

// HasTextInFile is a helper method to assert that file contains the supplied text
func (s *testSuite) HasTextInFile(file string, texts ...string) {
	f, err := ioutil.ReadFile(file)
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
	err := cmd.Run(s.ctl)
	s.Error(err)
}
