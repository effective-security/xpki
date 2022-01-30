package cli

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/effective-security/xpki/x/ctl"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite
	tmpdir string
	ctl    *Cli
	// Out is the outpub buffer
	Out bytes.Buffer

	appFlags []string

	rootCert string
	rootKey  string
}

func (s *testSuite) SetupSuite() {
	s.tmpdir = filepath.Join(os.TempDir(), "/tests/xpki", "mockhsm")
	err := os.MkdirAll(s.tmpdir, 0777)
	s.Require().NoError(err)

	s.ctl = &Cli{}

	s.ctl.WithErrWriter(&s.Out).
		WithWriter(&s.Out)

	parser, err := kong.New(s.ctl,
		kong.Name("hsm-tool"),
		kong.Description("CLI tool for HSM or KMS"),
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
	if len(flags) == 0 {
		flags = []string{"--cfg", "inmem"}
	}
	_, err = parser.Parse(flags)
	if err != nil {
		s.FailNow("unexpected error parsing: %+v", err)
	}
}

func (s *testSuite) TearDownSuite() {
	os.RemoveAll(s.tmpdir)
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
