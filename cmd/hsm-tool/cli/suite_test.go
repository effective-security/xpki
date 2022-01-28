package cli

import (
	"bytes"

	"github.com/alecthomas/kong"
	"github.com/effective-security/xpki/x/ctl"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite

	ctl *Cli
	// Out is the outpub buffer
	Out bytes.Buffer
}

func (s *testSuite) SetupTest() {

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

	_, err = parser.Parse([]string{"--cfg=inmem"})
	if err != nil {
		s.FailNow("unexpected error parsing: %+v", err)
	}
}

func (s *testSuite) TearDownTest() {
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
