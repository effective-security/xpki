# xpki

[![Coverage Status](https://coveralls.io/repos/github/effective-security/xpki/badge.svg?branch=main)](https://coveralls.io/github/effective-security/xpki?branch=main)

Library for working with certificates and keys

## Requirements

1. GoLang 1.21+
1. SoftHSM2

## Contribution

* `make all` complete build and test
* `make test` run the tests
* `make testshort` runs the tests skipping the end-to-end tests and the code coverage reporting
* `make covtest` runs the tests with end-to-end and the code coverage reporting
* `make coverage` view the code coverage results from the last make test run.
* `make generate` runs go generate to update any code generated files
* `make fmt` runs go fmt on the project.
* `make lint` runs the go linter on the project.

run `make all` once, then run `make build` or `make test` as needed.

First run:

    make all

Tests:

    make test

Optionally run golang race detector with test targets by setting RACE flag:

    make test RACE=true

Review coverage report:

    make covtest coverage

## Environment 

To work with keys on AWK KMS simulator container, set AWS environment to test values:

```
export AWS_ACCESS_KEY_ID=notusedbyemulator
export AWS_SECRET_ACCESS_KEY=notusedbyemulator
export AWS_DEFAULT_REGION=us-west-2
```

## Tools

- [hsm-tool](cmd/hsm-tool/README.md)
- [xpki-tool](cmd/xpki-tool/README.md)