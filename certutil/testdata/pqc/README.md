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

The keys are test material and protect nothing.
