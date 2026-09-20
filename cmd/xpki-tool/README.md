# xpki-tool

## Installation

```sh
go install github.com/effective-security/xpki/cmd/xpki-tool@latest
```

## Usage

```sh
Usage: xpki-tool <command> [flags]

PKI tools

Flags:
  -h, --help         Show context-sensitive help.
      --timeout=3    HTTP timeout in seconds

Commands:
  csr-info         print CSR info
  crl info         print CRL info
  crl fetch        fetch CRL
  cert info        print certificate info
  cert validate    validates certificate
  ocsp info        prints OCSP info
  ocsp fetch       fetch OCSP from certificate

Run "xpki-tool <command> --help" for more information on a command.
```

## Commands

### xpki-tool csr-info

```sh
Usage: xpki-tool csr-info <csr> [flags]

print CSR info

Arguments:
  <csr>    CSR file name

Flags:
  -h, --help         Show context-sensitive help.
      --timeout=3    HTTP timeout in seconds
```

### xpki-tool cert info

```sh
Usage: xpki-tool cert info <in> [flags]

print certificate info

Arguments:
  <in>    certificate file name

Flags:
  -h, --help                Show context-sensitive help.
      --timeout=3           HTTP timeout in seconds

      --out=STRING          optional, output file to save parsed certificates
      --not-after=STRING    optional, filter certificates by NotAfter time
      --no-expired          optional, filter non-expired certificates
      --extensions          optional, print extensions values
```

### xpki-tool cert validate

```sh
Usage: xpki-tool cert validate <cert> [flags]

validates certificate

Arguments:
  <cert>    certificate file name

Flags:
  -h, --help            Show context-sensitive help.
      --timeout=3       HTTP timeout in seconds

      --ca=STRING       optional, CA bundle file
      --root=STRING     optional, Trusted Roots file
      --out=STRING      optional, output file to save certificate chain
      --revocation      optional, validate certificate revocation status
      --proxy=STRING    optional, proxy address or DC name
      --with-aia        optional, enable AIA to fetch intermediates
```

### xpki-tool crl info

```sh
Usage: xpki-tool crl info <in>

print CRL info

Arguments:
  <in>    DER-encoded CRL

Flags:
  -h, --help         Show context-sensitive help.
      --timeout=3    HTTP timeout in seconds
```

### xpki-tool crl fetch

```sh
Usage: xpki-tool crl fetch --output=STRING <cert> [flags]

fetch CRL

Arguments:
  <cert>    certificate file name

Flags:
  -h, --help             Show context-sensitive help.
      --timeout=3        HTTP timeout in seconds

      --output=STRING    output folder name
      --all              fetch entire chain
      --proxy=STRING     optional, proxy address or DC name
      --print
```

### xpki-tool ocsp info

```sh
Usage: xpki-tool ocsp info <in> [flags]

prints OCSP info

Arguments:
  <in>    OCSP file name

Flags:
  -h, --help             Show context-sensitive help.
      --timeout=3        HTTP timeout in seconds

      --issuer=STRING
```

### xpki-tool ocsp fetch

```sh
Usage: xpki-tool ocsp fetch <cert> [flags]

fetch OCSP from certificate

Arguments:
  <cert>    certificate file name

Flags:
  -h, --help            Show context-sensitive help.
      --timeout=3       HTTP timeout in seconds

      --ca=STRING       optional, CA bundle file
      --out=STRING      output folder name
      --proxy=STRING    optional, proxy address or DC name
      --print
```
