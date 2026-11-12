# hsm-tool

## Installation

```sh
go install github.com/effective-security/xpki/v2/cmd/hsm-tool@latest
```

## Usage

```sh
Usage: hsm-tool --cfg=STRING <command> [flags]

CLI tool for HSM or KMS

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

Commands:
  hsm key list        list keys
  hsm key info        print key information
  hsm key generate    generate key
  hsm key remove      delete key
  csr create          create certificate request
  csr gen-cert        create CSR and sign certificate
  csr sign            sign certificate

Run "hsm-tool <command> --help" for more information on a command.
```

## Commands

### hsm-tool hsm key list

```sh
Usage: hsm-tool hsm key list --cfg=STRING [flags]

list keys

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

      --token=STRING         specifies slot token (optional)
      --serial=STRING        specifies slot serial (optional)
      --prefix=STRING        specifies key label prefix (optional)
      --label=STRING         specifies the exact key label (optional)
      --usage=STRING         lists keys with one of the usages: sign,encrypt
                             (optional)
      --type=TYPE,...        lists keys of the types: RSA,ECDSA,ML-DSA (default:
                             all three)
      --tag=KEY=VALUE;...    lists keys with the tag or cloud label name=value;
                             repeat the flag for several (not supported by
                             PKCS#11)
      --state=STATE,...      lists keys in the states:
                             enabled,disabled,pending_deletion,destroyed,unavailable,
                             or all (default: enabled,disabled)
      --limit=INT            lists at most this number of keys of a token
                             (default: all)
      --all                  lists keys of every type, including symmetric and
                             MAC keys
```

### hsm-tool hsm key info

```sh
Usage: hsm-tool hsm key info --cfg=STRING <id> [flags]

print key information

Arguments:
  <id>    key ID

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

      --token=STRING         slot token (optional)
      --serial=STRING        slot serial (optional)
      --public               print Public Key
      --tags                 print the tags or cloud labels of the key
```

### hsm-tool hsm key generate

```sh
Usage: hsm-tool hsm key generate --cfg=STRING --algo=STRING --size=INT --purpose=STRING --label=STRING [flags]

generate key

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

      --algo=STRING          algorithm: RSA|ECDSA|ML-DSA
      --size=INT             key size in bits, or the ML-DSA parameter set: 44, 65 or 87
      --purpose=STRING       purpose of the key: SIGN|ENCRYPT
      --label=STRING         name for generated key
      --output=STRING        location to write the key, if not set, the output
                             will be printed to STDOUT only
      --force                force to override key file if exists
```

### hsm-tool hsm key remove

```sh
Usage: hsm-tool hsm key remove --cfg=STRING <id> [flags]

delete key

Arguments:
  <id>    specifies key ID

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

      --token=STRING         specifies slot token (optional)
      --serial=STRING        specifies slot serial (optional)
```

### hsm-tool csr create

```sh
Usage: hsm-tool csr create --cfg=STRING --csr-profile=STRING --key-label=STRING [flags]

create certificate request

Flags:
  -h, --help                  Show context-sensitive help.
      --cfg=STRING            Location of HSM config file, as default crypto
                              provider
      --crypto=CRYPTO         Location of additional HSM config files
      --plain-key             Generate plain key
  -D, --debug                 Enable debug mode
  -l, --log-level="error"     Set the logging level (debug|info|warn|error)

      --csr-profile=STRING    file name with CSR profile
      --key-label=STRING      name for generated key
      --output=STRING         the optional prefix for output files; if not set,
                              the output will be printed to STDOUT only
```

### hsm-tool csr gen-cert

```sh
Usage: hsm-tool csr gen-cert --cfg=STRING --ca-config=STRING --csr-profile=STRING --profile=STRING --key-label=STRING [flags]

create CSR and sign certificate

Flags:
  -h, --help                  Show context-sensitive help.
      --cfg=STRING            Location of HSM config file, as default crypto
                              provider
      --crypto=CRYPTO         Location of additional HSM config files
      --plain-key             Generate plain key
  -D, --debug                 Enable debug mode
  -l, --log-level="error"     Set the logging level (debug|info|warn|error)

      --self-sign             generate self-signed cert
      --ca-cert=STRING        file name of the signing CA cert
      --ca-key=STRING         file name of the signing CA key
      --ca-config=STRING      file name with ca-config
      --csr-profile=STRING    file name with CSR profile
      --profile=STRING        certificate profile name from CA config
      --key-label=STRING      name for generated key
      --san=SAN,...           Subject Alt Names for generated cert
      --pem-info              Include certificate info in PEM file
      --output=STRING         the optional prefix for output files; if not set,
                              the output will be printed to STDOUT only
```

### hsm-tool csr sign

```sh
Usage: hsm-tool csr sign --cfg=STRING --ca-cert=STRING --ca-key=STRING --ca-config=STRING --profile=STRING <csr> [flags]

sign certificate

Arguments:
  <csr>    file name with pem-encoded CSR to sign

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

      --ca-cert=STRING       file name of the signing CA cert
      --ca-key=STRING        file name of the signing CA key
      --ca-config=STRING     file name with ca-config
      --profile=STRING       certificate profile name from CA config
      --san=SAN,...          Subject Alt Names for generated cert
      --aia-url=STRING       optional AIA to add to the certificate
      --ocsp-url=STRING      optional OCSP URL to add to the certificate
      --crl-url=STRING       optional CRL DP to add to the certificate
      --pem-info             Include certificate info in PEM file
      --output=STRING        the optional prefix for output files; if not set,
                             the output will be printed to STDOUT only
```
