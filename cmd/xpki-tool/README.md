# xpki-tool

## Installation

```sh
go install github.com/effective-security/xpki/cmd/xpki-tool
```

## Usage

```sh
Usage: xpki-tool <command>

PKI tools

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  csr-info         print CSR info
  ocsp-info        print OCSP info
  crl info         print CRL info
  crl fetch        fetch CRL
  cert info        print certificate info
  cert validate    validates certificate

Run "xpki-tool <command> --help" for more information on a command.
```