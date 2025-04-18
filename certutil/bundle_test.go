package certutil

import (
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCaBundle    = "testdata/ca-bundle.pem"
	testIntCaBundle = "testdata/int-bundle.pem"
)

// A helper structure that defines a BundleFromPEM test case.
type pemTest struct {
	// test name
	name string
	// PEM cert to be bundled
	cert []byte
	// Int CA file
	caBundleFile string
	// Root CA file
	rootCaFile string
	// expected error, if any
	expErr string
	// expected validity
	expValid bool
}

// BundleFromPEM test cases.
var pemTests = []pemTest{
	{
		name:         "GoDaddyIntermediateCert",
		cert:         GoDaddyIntermediateCert,
		caBundleFile: testIntCaBundle,
		rootCaFile:   testCaBundle,
		expErr:       "failed to bundle: unable to verify the certificate chain: x509: certificate signed by unknown authority (possibly because of \"x509: cannot verify signature: insecure algorithm SHA1-RSA\" while trying to verify candidate authority certificate \"The Go Daddy Group, Inc.\")",
	},
	{
		name:         "empty",
		cert:         []byte(""),
		caBundleFile: testIntCaBundle,
		rootCaFile:   testCaBundle,
		expErr:       "failed to bundle: failed to parse certificates",
	},
	{
		name:         "corruptCert",
		cert:         corruptCert,
		caBundleFile: testIntCaBundle,
		rootCaFile:   testCaBundle,
		expErr:       "failed to bundle: potentially malformed PEM",
	},
	{
		name:         "garbageCert",
		cert:         garbageCert,
		caBundleFile: testIntCaBundle,
		rootCaFile:   testCaBundle,
		expErr:       "failed to bundle: failed to parse certificate: x509: malformed algorithm identifier",
	},
	// {
	// 	name:         "selfSignedCert",
	// 	cert:         selfSignedCert,
	// 	caBundleFile: testIntCaBundle,
	// 	expValid:     true,
	// },
	{
		name:         "expiredCert",
		cert:         expiredCert,
		caBundleFile: testIntCaBundle,
		rootCaFile:   testCaBundle,
		expErr:       "failed to bundle: failed to parse certificate: x509: RSA key missing NULL parameters",
		expValid:     false,
	},
}

func intersLoader(t *testing.T, filename string) []byte {
	if filename != "" {
		caBundle, err := os.ReadFile(filename)
		require.NoError(t, err, "failed to load %s: %v", filename, err)
		return caBundle
	}
	return nil
}

func Test_VerifyBundle(t *testing.T) {
	for _, test := range pemTests {
		t.Run(test.name, func(t *testing.T) {
			inters := intersLoader(t, test.caBundleFile)
			rootCA := intersLoader(t, test.rootCaFile)
			bundle, status, err := VerifyBundleFromPEM(test.cert, inters, rootCA)
			if test.expErr != "" {
				if assert.Error(t, err, test.name) {
					assert.Equal(t, test.expErr, fmt.Sprintf("%v", err))
				}
			} else {
				if assert.NoError(t, err, test.name) {
					assert.NotNil(t, bundle, test.name)
					assert.Equal(t, test.expValid, !status.IsUntrusted())
					if test.expValid {
						assert.False(t, status.IsExpiring())
						assert.Greater(t, bundle.ExpiresInHours(), time.Duration(0))
					}
				}
			}
		})
	}
}

func Test_LoadAndVerifyBundleFromPEM(t *testing.T) {
	bundle, status, err := LoadAndVerifyBundleFromPEM(
		"testdata/test-server.pem",
		"testdata/ca-bundle.pem",
		"testdata/test-server-rootca.pem")
	require.NoError(t, err)
	assert.False(t, status.IsUntrusted())
	assert.Equal(t, 2, len(bundle.Chain))
	require.NotNil(t, bundle.Cert)
	assert.Equal(t, "localhost", bundle.Cert.Subject.CommonName)
	require.NotNil(t, bundle.IssuerCert)
	assert.Equal(t, "[TEST] Issuing CA One Level 1", bundle.IssuerCert.Subject.CommonName)
	require.NotNil(t, bundle.RootCert)
	assert.Equal(t, "[TEST] Root CA One", bundle.RootCert.Subject.CommonName)

	crt := FindIssuer(bundle.Cert, bundle.Chain, bundle.RootCert)
	require.NotNil(t, crt)
	assert.Equal(t, "[TEST] Issuing CA One Level 1", crt.Subject.CommonName)

	_, err = CreateOCSPRequest(bundle.Cert, bundle.IssuerCert, crypto.SHA256)
	require.NoError(t, err)
	_, err = CreateOCSPRequest(bundle.Cert, bundle.Cert, crypto.SHA256)
	assert.EqualError(t, err, "invalid chain: issuer does not match")
}

func Test_SortBundlesByExpiration(t *testing.T) {
	bundles := []*Bundle{
		{
			Subject: &pkix.Name{CommonName: "5"},
			Expires: time.Now().UTC().Add(time.Second * 5),
		},
		{
			Subject: &pkix.Name{CommonName: "60"},
			Expires: time.Now().UTC().Add(time.Second * 60),
		},
		{
			Subject: &pkix.Name{CommonName: "65"},
			Expires: time.Now().UTC().Add(time.Second * 65),
		},
		{
			Subject: &pkix.Name{CommonName: "30"},
			Expires: time.Now().UTC().Add(time.Second * 30),
		},
	}

	sorted := SortBundlesByExpiration(bundles)
	require.NotNil(t, sorted)
	if assert.Equal(t, len(bundles), len(sorted)) {
		assert.Equal(t, "65", sorted[0].Subject.CommonName)
		assert.Equal(t, "60", sorted[1].Subject.CommonName)
		assert.Equal(t, "30", sorted[2].Subject.CommonName)
		assert.Equal(t, "5", sorted[3].Subject.CommonName)
	}
}

// GoDaddyRootCert valid until year 2034
var GoDaddyRootCert = []byte(`-----BEGIN CERTIFICATE-----
	MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh
	MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE
	YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3
	MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo
	ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg
	MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN
	ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA
	PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w
	wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi
	EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY
	avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+
	YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE
	sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h
	/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5
	IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj
	YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
	ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy
	OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P
	TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ
	HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER
	dEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf
	ReYNnyicsbkqWletNw+vHX/bvZ8=
	-----END CERTIFICATE-----`)

// GoDaddyIntermediateCert valid until year 2026
var GoDaddyIntermediateCert = []byte(`-----BEGIN CERTIFICATE-----
MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMx
ITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28g
RGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYw
MTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMH
QXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5j
b20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j
b20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3H
KrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQm
VZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpR
SgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRT
cDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ
6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEu
MB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDS
kdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEB
BCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0f
BD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBv
c2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUH
AgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAO
BgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IG
OgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMU
A2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o
0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTX
RE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuH
qDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWV
U+4=
-----END CERTIFICATE-----`)

// This is the same GoDaddy cert above except the last line is corrupted.
var corruptCert = []byte(`-----BEGIN CERTIFICATE-----
MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVMx
ITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28g
RGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExMTYw
MTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UECBMH
QXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5j
b20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j
b20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTtwY6vj3D3H
KrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqVTr9vcyOdQm
VZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aLGbqGmu75RpR
SgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo7RJlbmr2EkRT
cDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgWJCJjPOq8lh8BJ
6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAwEAAaOCATIwggEu
MB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVHSMEGDAWgBTSxLDS
kdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEAMDMGCCsGAQUFBwEB
BCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWRkeS5jb20wRgYDVR0f
BD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBv
c2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVHSAAMDgwNgYIKwYBBQUH
AgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeTAO
BgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBANKGwOy9+aG2Z+5mC6IG
OgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPIUyIXvJxwqoJKSQ3kbTJSMU
A2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL5CkKSkB2XIsKd83ASe8T+5o
0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9p0iRFEUOOjZv2kWzRaJBydTX
RE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsxuxN89txJx9OjxUUAiKEngHUuH
qDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZEjYx8WnM25sgVjOuH0aBsXBTWV
CORRUPTED
-----END CERTIFICATE-----`)

// A garbage cert, which can be decoded into ill-formed cert
var garbageCert = []byte(`-----BEGIN CERTIFICATE-----
MIICATCCAWoCCQDidF+uNJR6czANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB
cyBQdHkgTHRkMB4XDTEyMDUwMTIyNTUxN1oXDTEzMDUwMTIyNTUxN1owRTELMAkG
A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
nodhz31kLEJoeLSkRmrv8l7exkGtO0REtIbirj9BBy64ZXVBE7khKGO2cnM8U7yj
w7Ntfh+IvCjZVA3d2XqHS3Pjrt4HmU/cGCONE8+NEXoqdzLUDPOix1qDDRBvXs81
IFdpZGdpdHMgUHR5IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtpjl
KAV2qh6CYHZbdqixhDerjvJcD4Nsd7kExEZfHuECAwEAATANBgkqhkiG9w0BAQUF
AAOBgQCyOqs7+qpMrYCgL6OamDeCVojLoEp036PsnaYWf2NPmsVXdpYW40Foyyjp
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
iv5otkxO5rxtGPv7o2J1eMBpCuSkydvoz3Ey/QwGqbBwEXQ4xYCgra336gqW2KQt
+LnDCkE8f5oBhCIisExc2i8PDvsRsY70g/2gs983ImJjVR8sDw==
-----END CERTIFICATE-----`)

// A expired cert
var expiredCert = []byte(`-----BEGIN CERTIFICATE-----
MIIB7jCCAVmgAwIBAgIBADALBgkqhkiG9w0BAQUwJjEQMA4GA1UEChMHQWNtZSBD
bzESMBAGA1UEAxMJMTI3LjAuMC4xMB4XDTEyMDkwNzIyMDAwNFoXDTEzMDkwNzIy
MDUwNFowJjEQMA4GA1UEChMHQWNtZSBDbzESMBAGA1UEAxMJMTI3LjAuMC4xMIGd
MAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEAm6f+jkP2t5q/vM0YAUZZkhq/EAYD+L1C
MS59jJOLomfDnKUWOGKi/k7URBg1HNL3vm7/ESDazZWFy9l/nibWxNkSUPkQIrvr
GsNivkRUzXkwgNX8IN8LOYAQ3BWxAqitXTpLjf4FeCTB6G59v9eYlAX3kicXRdY+
cqhEvLFbu3MCAwEAAaMyMDAwDgYDVR0PAQH/BAQDAgCgMA0GA1UdDgQGBAQBAgME
MA8GA1UdIwQIMAaABAECAwQwCwYJKoZIhvcNAQEFA4GBABndWRIcfi+QB9Sakr+m
dYnXTgYCnFio53L2Z+6EHTGG+rEhWtUEGhL4p4pzXX4siAnjWvwcgXTo92cafcfi
uB7wRfK+NL9CTJdpN6cdL+fiNHzH8hsl3bj1nL0CSmdn2hkUWVLbLhSgWlib/I8O
aq+K7aVrgHkPnWeRiG6tl+ZA
-----END CERTIFICATE-----`)

// A self-signed cert
var selfSignedCert = []byte(`-----BEGIN CERTIFICATE-----
MIIERTCCAy2gAwIBAgIJAORAsvx6MZO7MA0GCSqGSIb3DQEBBQUAMHQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG
A1UEChMOQ2xvdWRGbGFyZSBMTEMxETAPBgNVBAsTCFNlY3VyaXR5MRQwEgYDVQQD
Ewt0ZXN0c3NsLmxvbDAeFw0xNDA0MDQyMjM4MzhaFw0yNDA0MDEyMjM4MzhaMHQx
CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNj
bzEXMBUGA1UEChMOQ2xvdWRGbGFyZSBMTEMxETAPBgNVBAsTCFNlY3VyaXR5MRQw
EgYDVQQDEwt0ZXN0c3NsLmxvbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMKNLxpsnT37jSYkP9LVjw050Nmt1YMcEPwLe8zGUr8QzTWQ194Z9Ik/qYS0
UpQlx7+8UBoCanDTYuNKarHhmj4nZp+gc3mWWlaJKRnCJZ+Ru18x2lg9BzG4MwPQ
63ve0WxZ69/6J3lx53ertDgcD7S4v71BaeE10miBeJLK3JkV6fgGGfGRAGwU9vfm
OBbPTAw2SRdB1AaYTHaT4ANwUI7vvkIPrNuneTjOqlN9DAroUNIkXhV+fSmncRxi
RCAfP8/4BZdZ9C4TTKUpdAVUe1LUcHygK2f3YtOx8qJLCRMTRMYccSI1Y1idhX1s
SKIDDrOuELb+pGgno5PCe6i6MWcCAwEAAaOB2TCB1jAdBgNVHQ4EFgQUCkxuIVbR
+I8Z0A547Xj1R57ceXUwgaYGA1UdIwSBnjCBm4AUCkxuIVbR+I8Z0A547Xj1R57c
eXWheKR2MHQxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2Fu
IEZyYW5jaXNjbzEXMBUGA1UEChMOQ2xvdWRGbGFyZSBMTEMxETAPBgNVBAsTCFNl
Y3VyaXR5MRQwEgYDVQQDEwt0ZXN0c3NsLmxvbIIJAORAsvx6MZO7MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAKFaOjVRXCNsOznpZe0478mIFK6mNwwi
ZrLcrEUZ0FIOcPwsnQXd/HmrR4MVj3z3U62mE6qFo+07yJnnXdKBJ9ThjmNu6c4S
dk2xPbKTuACF7UhMgPlac0tEp/KSJTaMcjl23H+ol80LZ/t1113XSAZYHWsAgTjC
905kp66Gcq7c+GBgrBqR4e6Z2GYCeAk5aMy5f5s90teW2bIZE0hG1mFz1e25l9lI
SkAp0gZusX4yxqoSBqKmKXBkjrW5vkKJZjP51c7fuhfuAyNfxZF4Cz9SS0YSG8eh
H5kVbpLP+eSYMqF110qqjAo4tkgBquF6IppA+HQ66DN64+TeiXb3f2Y=
-----END CERTIFICATE-----`)

// An expired bundle
var expiredBundlePEM = []byte(`-----BEGIN CERTIFICATE-----
MIIEQjCCAiqgAwIBAgIUSPPw6BHm4JN47rB9Nev1ebExqw4wDQYJKoZIhvcNAQEL
BQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQKEwpDbG91ZEZsYXJlMRwwGgYDVQQLExNT
eXN0ZW1zIEVuZ2luZWVyaW5nMR0wGwYDVQQDExRjbG91ZGZsYXJlLWludGVyLmNv
bTAeFw0xNjAyMTgwMTEyMDBaFw0zNjAyMTMwMTEyMDBaMIGLMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzET
MBEGA1UEChMKQ2xvdWRGbGFyZTEcMBoGA1UECxMTU3lzdGVtcyBFbmdpbmVlcmlu
ZzEcMBoGA1UEAxMTY2xvdWRmbGFyZS1sZWFmLmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABIxG/fG9y/gjlAXvB77beERLbBooN98FGFAxVUA5IglylvgmfNxU
mI8mM2Uw9tzOLm9vORAraSSM4/6iSpCJreCjZjBkMA4GA1UdDwEB/wQEAwICBDAS
BgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSpzVbLqJgME2OAVKfxa1pZd3fI
rjAfBgNVHSMEGDAWgBSIYLoYpHe4QQQb1e93UcJbFLogPzANBgkqhkiG9w0BAQsF
AAOCAgEAosHIEiZcAHFGRA3e/5c9cCXWYzKT53i6uFOU7qNhbraTwpSa5V2pYF+l
oNr1BHoWBO7R/Fal4N9hMWIGtMxWItg1GsuQix8UFAuFA6f0pVXukimrWOXXB8pP
vEkSpY+iYJxZoNPv1iAt8OGEFvJLOzICjIx+JZbDrX9xCM6Xws5T4Vh5i9gLAD9k
zO5LW2aQWACiynl8poij6qI8h1vcLFPNkjqe3RfuqDZo/h4HHI7zOUnIo9rC2Ooh
9MfE5PI5Ion5zLWjLetDk3sfJZxNfTC+DTxzne51J/05Fbq45zK43/B2204KWk0f
JwjNQWvWqTAkAjHzok4QiW/645crDRS6qPJ/0+o0R5y23khGi/LgDogi+1U2mBOw
gNflC00NUZCbY/xb4xiMQykuqgBFiaCXesGbtGwlFso6/vyORWx/K2XF6yTAVVWd
hzd4h25jlwVM8RrNV64B9z5lHch0vXOUADXY2/+Jo+hL/NLBYiWR+mCXWV1oaNI9
673+yoWsFyXzzZwKIH6qGI5Wq2TLC3XxBDAymzHuAQzEiQXHQgfn0LjpL8zt5oxc
3Wvw0t1ioLP7tZnwV4OAKX4UKLNNeik0jNvAJQB6VgYSheSVp7QdhAZzThMM2vQf
T/RgXlnELyT9B3eOWREjC7aBinYYvn81fRdRRYg1pljZaDJ0JeE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEfTCCA+agAwIBAgIUFalofeaKAEmnWkBXWu4lkwmmh3IwDQYJKoZIhvcNAQEF
BQAwfTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xEzARBgNVBAoMCkNsb3VkRmxhcmUxFDASBgNVBAsMC0RF
Vl9URVNUSU5HMRYwFAYDVQQDDA1DRlNTTF9URVNUX0NBMB4XDTE2MDIxODAxMTIw
MFoXDTE2MDIxODAxMTIwMVowgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxp
Zm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQKEwpDbG91ZEZs
YXJlMRwwGgYDVQQLExNTeXN0ZW1zIEVuZ2luZWVyaW5nMR0wGwYDVQQDExRjbG91
ZGZsYXJlLWludGVyLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AOUKdX6+PSxU/LxKocsCUj7HCc+FaDOPZV68Po3PVm7UF5DmbnLgJYJ/4aZEZM/v
5r8LnXQXDqumYicHQ2DHHBDasLTx8m0KeKOUYf9WMQ8gdjmVFoCiZwzxGDHok66/
0Glkkqmv2nJQxXncl5ZFta4sfmcQx3KT02l61LaBbG3j8PbRCWEr+0eRE6twuYRR
13AgZ3ATwnMjzxzvsW67qmAy0cq+XgYYfTK9vhPs+8J0fxXa0Iftu3yuhd30xLIV
XLu45GR+i6KnsSxVERSaVxjkS+lHXjUpdtmqI5CK6wn67vqYRRA2TzAJHX8Jb+KL
2/UEo5WNfAJ8S0heODQA8nHVU1JIfpegOlQRMv55DgnQUv1c1uwO5hqvv7MPQ3X/
m9Kjccs1FBH1/SVuzKyxYEQ34LErX3HI+6avbVnRtTR/UHkfnZVIXSrcjUm73BGj
33hrtiKl0ZyZnaUKGZPuvebOUFNiXemhTbqrfi/zAb1Tsm/h+xkn5EZ5sMj5NHdA
bpih3TqX2gRhnFZcFjtJM6zzC5O7eG5Kdqf8iladXTXtWxzrUPkb5CupzFl1dyS3
dqdkoIXvkmlScnu+6jBOaYeVvwogxr2Y69y4Zfg/qbPyBOLZquX9ovbuSP1DQmC/
/LV5t7YHHY/1MXr5U0MMvcn+9JWUV6ou3at4AgEqfK0vAgMBAAGjZjBkMA4GA1Ud
DwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSIYLoYpHe4
QQQb1e93UcJbFLogPzAfBgNVHSMEGDAWgBS4Xu+uZ1C31vMH5Wq+VbNnOg2SPjAN
BgkqhkiG9w0BAQUFAAOBgQAnGnLG3r4g+0bLkeeh1Y71pL0Ui1LnvCA1v+yVDCd0
G9pj7cnHHXjnp4Pic6pP9uwxBAiUC6rzjpKrm1ULYMoQPLAYmwJiz+8yiE5vpMCA
Ov3LFPDNAbGF2wavwpCVolnVgHzPSFTEXN53DdXdVhcQ207P+zWNCNDF4Q33WSfm
Dw==
-----END CERTIFICATE-----`)
