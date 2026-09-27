include .project/gomod-project.mk
BUILD_FLAGS=
# LDFLAGS sets the build version reported by the CLIs (internal/version).
LDFLAGS=-ldflags "-X github.com/effective-security/xpki/internal/version.build=$(GIT_VERSION)"

export COVERAGE_EXCLUSIONS="tests|testca|main\.go|clisuite|testsuite\.go|mocks\.go"
export XPKI_INTEGRATION=required

export AWS_ACCESS_KEY_ID=notusedbyemulator
export AWS_SECRET_ACCESS_KEY=notusedbyemulator
export AWS_DEFAULT_REGION=us-west-2
# make test/covtest (and CI) fail when a test fixture is missing (internal/testenv)

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

# Tool versions (XPKI-096). They are pinned to releases tested with this
# module's Go version and .golangci.yaml; `@latest` let a golangci-lint major
# bump break the lint configuration. To update: change the version here, run
# `make tools lint covtest docs` on a clean checkout, and commit the result
# together with any .golangci.yaml change the new release needs.
GOLANGCI_LINT_VERSION ?= v2.13.2
COV_REPORT_VERSION ?= v1.1.0
GOVULNCHECK_VERSION ?= v1.8.0
GOMARKDOC_VERSION ?= v1.1.0

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/go-phorce/cov-report/cmd/cov-report@$(COV_REPORT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@$(GOMARKDOC_VERSION)

version:
	echo "$(GIT_VERSION)"

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
	go build ${BUILD_FLAGS} ${LDFLAGS} -o ${PROJ_ROOT}/bin/hsm-tool ./cmd/hsm-tool
	md5sum ./bin/hsm-tool >> ./build_log.txt
	echo "*** Building xpki-tool"
	go build ${BUILD_FLAGS} ${LDFLAGS} -o ${PROJ_ROOT}/bin/xpki-tool ./cmd/xpki-tool
	md5sum ./bin/xpki-tool >> ./build_log.txt

.PHONY: test-scripts
test-scripts:
	bash scripts/config-softhsm_test.sh

hsmconfig: test-scripts
	echo "*** Running hsmconfig"
	go build ${BUILD_FLAGS} ${LDFLAGS} -o "${PROJ_ROOT}/bin/hsm-tool" ./cmd/hsm-tool
	mkdir -p ~/softhsm2 /tmp/xpki
	./scripts/config-softhsm.sh \
		--pin-file ~/softhsm2/xpki_pin_unittest.txt \
		--generate-pin \
		-s xpki_unittest \
		-o /tmp/xpki/softhsm_unittest.json \
		--delete
	SOFTHSM2_CONF="$${SOFTHSM2_CONF_DIR:-$$HOME/.config/softhsm2}/softhsm2.conf" \
		"${PROJ_ROOT}/bin/hsm-tool" --cfg /tmp/xpki/softhsm_unittest.json hsm list
	echo ""

start-local-kms:
	echo "*** starting local-kms"
	docker compose -f docker-compose.yml -p xpki-kms up -d --force-recreate --remove-orphans

docs:
	echo "*** generating Docs"
	rm -rf Documentation/api
	mkdir -p Documentation/api
	for pkg in $$(go list ./... | grep -v '/tests/'); do \
		out=Documentation/api/$$(echo $$pkg | sed 's#${REPO_NAME}/##; s#/#_#g').md; \
		gomarkdoc --output $$out --repository.default-branch main $$pkg || exit 1; \
	done
	echo "API reference written to Documentation/api"
	# hsm-tool
	echo "\`\`\`bash" > ./Documentation/cli/hsm-tool.md
	bin/hsm-tool --help >> ./Documentation/cli/hsm-tool.md
	echo "\`\`\`" >> ./Documentation/cli/hsm-tool.md
	# xpki-tool
	echo "\`\`\`bash" > ./Documentation/cli/xpki-tool.md
	bin/xpki-tool --help >> ./Documentation/cli/xpki-tool.md
	echo "\`\`\`" >> ./Documentation/cli/xpki-tool.md
