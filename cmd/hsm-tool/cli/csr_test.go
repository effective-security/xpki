package cli

import (
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/x/guid"
	"github.com/stretchr/testify/suite"
)

type csrSuite struct {
	testSuite
}

func TestCsrSuite(t *testing.T) {
	s := new(csrSuite)
	s.appFlags = []string{
		"--cfg", "../../../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json",
		"--crypto", "../../../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml",
	}
	suite.Run(t, s)
}

func (s *csrSuite) TestCreate() {
	s.createRootCA()

	label := "cert" + guid.MustCreate()
	cmd := CsrCreateCmd{
		CsrProfile: "../../../authority/testdata/csrprofiles/trusty_client.yaml",
		KeyLabel:   label,
	}
	err := cmd.Run(s.ctl)
	s.Require().NoError(err)

	cmd.Output = filepath.Join(s.tmpdir, label)
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	s.HasTextInFile(cmd.Output+".csr", "REQUEST")
	s.HasTextInFile(cmd.Output+".key", "private")
}

func (s *csrSuite) TestGenCert() {
	s.createRootCA()

	cmd := GenCertCmd{
		CACert:     s.rootCert,
		CAKey:      s.rootKey,
		CAConfig:   "../../../authority/testdata/ca-config.bootstrap.yaml",
		CsrProfile: "../../../authority/testdata/csrprofiles/trusty_server.yaml",
		KeyLabel:   "server" + guid.MustCreate(),
		San:        []string{"ekspand.com", "ca@ekspand.com", "10.1.1.12"},
		Profile:    "server",
	}

	// to stdout
	err := cmd.Run(s.ctl)
	s.Require().NoError(err)

	// to file
	cmd.Output = filepath.Join(s.tmpdir, cmd.KeyLabel)
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
	s.Require().NoError(err)
	s.HasTextInFile(cmd.Output+".pem", "CERTIFICATE")
	s.HasTextInFile(cmd.Output+".key", "private")
}

func (s *csrSuite) TestSignCert() {
	s.createRootCA()

	createCSR := CsrCreateCmd{
		CsrProfile: "../../../authority/testdata/csrprofiles/delegated_l1_ca.yaml",
		KeyLabel:   "*",
		Output:     filepath.Join(s.tmpdir, "server"+guid.MustCreate()),
	}
	err := createCSR.Run(s.ctl)
	s.Require().NoError(err)

	req := createCSR.Output + ".csr"
	s.HasTextInFile(req, "REQUEST")

	// to file
	cmd := CsrSignCmd{
		CACert:   s.rootCert,
		CAKey:    s.rootKey,
		CAConfig: "../../../authority/testdata/ca-config.dev.yaml",
		Csr:      req,
		San:      []string{"ekspand.com", "ca@ekspand.com", "10.1.1.12"},
		Profile:  "DELEGATED_L1_CA",
		Output:   createCSR.Output,
	}

	err = cmd.Run(s.ctl)
	s.Require().NoError(err)

	s.Require().NoError(err)
	s.HasTextInFile(cmd.Output+".pem", "CERTIFICATE")
	s.HasTextInFile(cmd.Output+".key", "private")

	// to stdout
	cmd.Output = ""
	err = cmd.Run(s.ctl)
	s.Require().NoError(err)
}

func (s *testSuite) createRootCA() {
	if s.rootCert != "" {
		return
	}

	label := "root" + guid.MustCreate()
	output := filepath.Join(s.tmpdir, label)

	cmd := GenCertCmd{
		SelfSign:   true,
		CAConfig:   "../../../authority/testdata/ca-config.bootstrap.yaml",
		CsrProfile: "../../../authority/testdata/csrprofiles/root_ca.yaml",
		KeyLabel:   label,
		Profile:    "ROOT",
		Output:     output,
	}

	err := cmd.Run(s.ctl)
	s.Require().NoError(err)

	s.rootCert = output + ".pem"
	s.rootKey = output + ".key"
	s.HasTextInFile(s.rootCert, "CERTIFICATE")
	s.HasTextInFile(s.rootKey, "private")
}
