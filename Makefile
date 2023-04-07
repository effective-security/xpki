include .project/gomod-project.mk
export GO111MODULE=on
BUILD_FLAGS=

export AWS_ACCESS_KEY_ID=notusedbyemulator
export AWS_SECRET_ACCESS_KEY=notusedbyemulator
export AWS_DEFAULT_REGION=us-west-2

.PHONY: *

.SILENT:

default: help

all: clean tools generate change_log start-local-kms hsmconfig covtest

#
# clean produced files
#
clean:
	go clean ./...
	rm -rf \
		${COVPATH} \
		${PROJ_BIN}

tools:
	go install golang.org/x/tools/cmd/stringer@latest
	go install github.com/go-phorce/cov-report/cmd/cov-report@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.2
	go install github.com/go-delve/delve/cmd/dlv@v1.20.1
	go install github.com/mattn/goveralls@latest

version:
	echo "*** building version"
	gofmt -r '"GIT_VERSION" -> "$(GIT_VERSION)"' internal/version/current.template > internal/version/current.go

change_log:
	echo "Recent changes" > ./change_log.txt
	echo "Build Version: $(GIT_VERSION)" >> ./change_log.txt
	echo "Commit: $(GIT_HASH)" >> ./change_log.txt
	echo "==================================" >> ./change_log.txt
	git log -n 20 --pretty=oneline --abbrev-commit >> ./change_log.txt

hashbin:
	mkdir -p bin && echo "hash:" > ./build_log.txt

build: hashbin
	echo "*** Building hsm-tool"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/hsm-tool ./cmd/hsm-tool
	md5sum ./bin/hsm-tool >> ./build_log.txt
	echo "*** Building xpki-tool"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/xpki-tool ./cmd/xpki-tool
	md5sum ./bin/xpki-tool >> ./build_log.txt

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

