# ML-DSA interoperability vectors

Generated on 2026-11-08 with OpenSSL 3.5.5 for the three FIPS 204 parameter
sets; `pqc_test.go` checks that Go parses and verifies them and that
`certutil` re-encodes the keys byte for byte.

```sh
for s in 44 65 87; do
  openssl genpkey -algorithm ML-DSA-$s -provparam ml-dsa.output_formats=seed-only -out mldsa$s.key
  openssl pkey -in mldsa$s.key -pubout -out mldsa$s.pub
  openssl req -new -key mldsa$s.key -subj "/CN=xpki ML-DSA-$s test/O=effective-security" \
    -addext "subjectAltName=DNS:mldsa$s.example.com" -out mldsa$s.csr
  openssl req -x509 -key mldsa$s.key -days 3650 -subj "/CN=xpki ML-DSA-$s test CA/O=effective-security" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out mldsa$s.crt
done
# OpenSSL's default private key output carries both the seed and the
# expanded key; crypto/x509 accepts only the seed form (RFC 9881).
openssl genpkey -algorithm ML-DSA-65 -out mldsa65-seed-and-expanded.key
```

| File                            | Content                                              |
| ------------------------------- | ---------------------------------------------------- |
| `mldsaNN.key`                   | PKCS#8 private key, seed form (54 bytes of DER)      |
| `mldsaNN.pub`                   | SubjectPublicKeyInfo                                 |
| `mldsaNN.csr`                   | CSR for `mldsaNN.example.com`, signed with ML-DSA-NN |
| `mldsaNN.crt`                   | Self-signed CA certificate, signed with ML-DSA-NN    |
| `mldsa65-seed-and-expanded.key` | PKCS#8 key in the form Go rejects                    |

The OCSP vectors were generated on 2026-11-09 with the same OpenSSL, from
`mldsa65.crt` as the CA, and `ocsp_mldsa_test.go` parses and verifies them.
The ML-DSA-44 key of the leaf certificate is not kept; `mldsa65-leaf.crt` is
both the certificate the responses describe and the delegated responder.

```sh
openssl genpkey -algorithm ML-DSA-44 -provparam ml-dsa.output_formats=seed-only -out leaf.key
openssl req -new -key leaf.key -subj "/CN=xpki ML-DSA-44 leaf/O=effective-security" -out leaf.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\n' > signer.ext
openssl x509 -req -in leaf.csr -CA mldsa65.crt -CAkey mldsa65.key -set_serial 0x1001 -days 3650 \
  -extfile signer.ext -out mldsa65-leaf.crt
printf 'V\t360101000000Z\t\t1001\tunknown\t/CN=xpki ML-DSA-44 leaf\n' > index.txt
openssl ocsp -issuer mldsa65.crt -cert mldsa65-leaf.crt -no_nonce -reqout req.der
ocsp="openssl ocsp -index index.txt -CA mldsa65.crt -reqin req.der -ndays 3650"
$ocsp -rsigner mldsa65.crt -rkey mldsa65.key -respout mldsa65-ocsp.der
$ocsp -rsigner mldsa65.crt -rkey mldsa65.key -respout mldsa65-ocsp-nocerts.der -resp_no_certs
$ocsp -rsigner mldsa65-leaf.crt -rkey leaf.key -respout mldsa65-ocsp-delegated.der
```

| File                         | Content                                                     |
| ---------------------------- | ----------------------------------------------------------- |
| `mldsa65-leaf.crt`           | ML-DSA-44 certificate, serial 0x1001, issued by `mldsa65.crt` with the OCSP signing EKU |
| `mldsa65-ocsp.der`           | `good` for serial 0x1001, signed by the CA, embeds the CA certificate |
| `mldsa65-ocsp-nocerts.der`   | The same, without an embedded certificate                   |
| `mldsa65-ocsp-delegated.der` | The same, signed by the ML-DSA-44 leaf, which is embedded   |

The keys are test material and protect nothing.
