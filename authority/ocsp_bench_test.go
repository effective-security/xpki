package authority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/effective-security/xpki/testca"
)

// BenchmarkSignOCSP measures OCSP signing and responder lookup with a warm
// responder cache for the CA key and a delegated responder (XPKI-052).
func BenchmarkSignOCSP(b *testing.B) {
	for _, mode := range []string{"ca", "delegated_warm"} {
		issuer, entity := ocspTestIssuer(b)
		if mode == "delegated_warm" {
			delegated := entity.Issue(
				testca.Subject(pkix.Name{CommonName: "Delegated responder"}),
				testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
				testca.KeyUsage(x509.KeyUsageDigitalSignature),
			)
			issuer.cfg.AIA.DelegatedOCSPProfile = delegatedProfile
			issuer.delegated.Store(&OCSPResponder{
				Cert:   delegated.Certificate,
				Signer: delegated.PrivateKey,
			})
		}
		req := &OCSPSignRequest{SerialNumber: big.NewInt(1), Status: OCSPStatusGood}
		b.Run(mode+"/sign", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := issuer.SignOCSP(req); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
		b.Run(mode+"/lookup", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := issuer.CreateDelegatedOCSPSigner(); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkDelegatedOCSPRetryWindow measures responder lookup while renewal
// is due but deferred: the CA expires within the OCSP expiry interval, so
// every responder is short-lived and renewal waits for the retry interval.
func BenchmarkDelegatedOCSPRetryWindow(b *testing.B) {
	issuer, _, _ := delegatedTestIssuer(b, testca.NotAfter(time.Now().Add(delegatedOCSPTTL/2)))
	if _, err := issuer.CreateDelegatedOCSPSigner(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := issuer.delegatedResponder(time.Now(), true); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkDelegatedOCSPCreate measures issuing a delegated responder, the
// cost of a cold start or renewal (key generation and a CA signature).
func BenchmarkDelegatedOCSPCreate(b *testing.B) {
	issuer, _, _ := delegatedTestIssuer(b)
	b.ReportAllocs()
	for b.Loop() {
		issuer.delegated.Store(nil)
		if _, err := issuer.CreateDelegatedOCSPSigner(); err != nil {
			b.Fatal(err)
		}
	}
}
