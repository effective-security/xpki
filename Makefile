include .project/gomod-project.mk
export GO111MODULE=on
BUILD_FLAGS=

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

build:
	echo "*** Building hsm-tool"
	go build ${BUILD_FLAGS} -o ${PROJ_ROOT}/bin/hsm-tool ./cmd/hsm-tool


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
	# Container state will be true (it's already running), false (exists but stopped), or missing (does not exist).
	# Annoyingly, when there is no such container and Docker returns an error, it also writes a blank line to stdout.
	# Hence the sed to trim whitespace.
	LKMS_CONTAINER_STATE=$$(echo $$(docker inspect -f "{{.State.Running}}" xpki-unittest-local-kms 2>/dev/null || echo "missing") | sed -e 's/^[ \t]*//'); \
	if [ "$$LKMS_CONTAINER_STATE" = "missing" ]; then \
		docker pull nsmithuk/local-kms && \
		docker run --network host \
			-d -e 'PORT=4599' \
			-p 4599:4599 \
			--name xpki-unittest-local-kms \
			nsmithuk/local-kms && \
			sleep 1; \
	elif [ "$$LKMS_CONTAINER_STATE" = "false" ]; then docker start xpki-unittest-local-kms && sleep 1; fi;
	echo ""
