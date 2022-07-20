include .project/gomod-project.mk
export GO111MODULE=on
BUILD_FLAGS=

export AWS_ACCESS_KEY_ID=notusedbyemulator
export AWS_SECRET_ACCESS_KEY=notusedbyemulator
export AWS_DEFAULT_REGION=us-west-2

.PHONY: *

.SILENT:

default: help

all: clean tools generate start-local-kms hsmconfig covtest

#
# clean produced files
#
clean:
	go clean ./...
	rm -rf \
		${COVPATH} \
		${PROJ_BIN}

tools:
	go install golang.org/x/tools/cmd/stringer
	go install github.com/go-phorce/cov-report/cmd/cov-report
	go install golang.org/x/lint/golint
	go install github.com/mattn/goveralls

version:
	echo "*** building version"
	gofmt -r '"GIT_VERSION" -> "$(GIT_VERSION)"' internal/version/current.template > internal/version/current.go

build:
	echo "*** Building hsm-tool"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/hsm-tool ./cmd/hsm-tool
	echo "*** Building xpki-tool"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/xpki-tool ./cmd/xpki-tool

coveralls-github:
	echo "Running coveralls"
	goveralls -v -coverprofile=coverage.out -service=github -package ./...

hsmconfig:
	echo "*** Running hsmconfig"
	mkdir -p ~/softhsm2 /tmp/xpki
	./scripts/config-softhsm.sh \
		--pin-file ~/softhsm2/xpki_pin_unittest.txt \
		--generate-pin \
		-s xpki_unittest \
		-o /tmp/xpki/softhsm_unittest.json \
		--list-slots --list-object --delete
	echo ""

start-local-kms:
	echo "*** starting local-kms"
	docker-compose -f docker-compose.yml -p xpki-kms up -d --force-recreate --remove-orphans

