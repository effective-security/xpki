// Package certutil provides utilities to work with certificates.
//
// A Bundler builds and verifies certificate chains. It trusts only the roots
// it is given, plus the platform trust store when WithSystemRoots(true) is
// set; without trust roots it defaults to Force, which checks signatures
// only. AIA downloads (WithAIA) are bounded by the WithHTTPClient timeout
// and the context given to BundleContext. One Bundler can be shared by
// goroutines; intermediates it learns over AIA are reused by later calls:
//
//	b, err := certutil.NewBundler(nil, intermediates,
//		certutil.WithSystemRoots(true),
//		certutil.WithAIA(true),
//	)
//	if err != nil {
//		return err
//	}
//	chain, err := b.BundleContext(ctx, []*x509.Certificate{leaf}, nil)
package certutil
