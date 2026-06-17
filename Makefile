export GO111MODULE := on
CUSTOM_LD_FLAGS ?=

all: generate-version-and-build

# Repo settings
GOMODULE = github.com/OpenNHP/opennhp/nhp

# Version and build settings
MAKEFLAGS += --no-print-directory
OS_NAME = $(shell uname -s | tr A-Z a-z)
GOPATH = $(shell go env GOPATH)
GOMOBILE = $(shell which gomobile 2>/dev/null || echo $(GOPATH)/bin/gomobile)
XCODE_APP = $(shell test -d /Applications/Xcode.app && echo found || echo "")
XCODE_SELECT = $(shell xcode-select -p 2>/dev/null | grep -q Xcode.app && echo found || echo "")

# Version number auto increment
TIMESTAMP=$(shell date +%y%m%d%H%M%S)
VERSION = $(shell cat nhp/version/VERSION).$(TIMESTAMP)
# Other version settings
COMMIT_ID = $(shell git show -s --format=%H)
COMMIT_TIME = $(shell git show -s --format=%cd --date=format:'%Y-%m-%d %H:%M:%S')
BUILD_TIME = $(shell date "+%Y-%m-%d %H:%M:%S")
# Built Package File Name
PACKAGE_FILE = opennhp-$(VERSION).tar.gz
# Go build flags
LD_FLAGS = "${CUSTOM_LD_FLAGS} -s -w -X '${GOMODULE}/version.Version=${VERSION}' -X '${GOMODULE}/version.CommitId=${COMMIT_ID}' -X '${GOMODULE}/version.CommitTime=${COMMIT_TIME}' -X '${GOMODULE}/version.BuildTime=${BUILD_TIME}'"

# Color definition
COLOUR_GREEN=\033[0;32m
COLOUR_RED=\033[0;31m
COLOUR_BLUE=\033[0;34m
END_COLOUR=\033[0m

# Plugins
NHP_SERVER_PLUGINS = ./examples/server_plugin

# Android environment settings
ANDROID_CC='${TOOLCHAIN}/bin/aarch64-linux-android21-clang'
ANDROID_CXX='${TOOLCHAIN}/bin/aarch64-linux-android21-clang++'

# eBPF compile
ifneq (,$(findstring ebpf,$(MAKECMDGOALS)))
    CLANG := $(shell command -v clang 2>/dev/null)
    ifeq ($(CLANG),)
        $(error "clang is not installed. Please install clang to compile eBPF programs.")
    endif
endif

EBPF_SRC_XDP = ./nhp/ebpf/xdp/nhp_ebpf_xdp.c
EBPF_SRC_TC_EGRESS = ./nhp/ebpf/xdp/tc_egress.c
EBPF_OBJ_XDP = ./release/nhp-ac/etc/nhp_ebpf_xdp.o
EBPF_OBJ_TC_EGRESS = ./release/nhp-ac/etc/tc_egress.o
CLANG_OPTS = -O2 -target bpf -g -Wall -I.

.PHONY: ebpf
ebpf: $(EBPF_OBJ_XDP) $(EBPF_OBJ_TC_EGRESS) generate-version-and-build
	@echo "$(COLOUR_GREEN)[eBPF] Full build completed$(END_COLOUR)"

$(EBPF_OBJ_XDP): $(EBPF_SRC_XDP)
	@mkdir -p $(@D)
	@echo "$(COLOUR_BLUE)[eBPF] Compiling: $< -> $@ $(END_COLOUR)"
	$(CLANG) $(CLANG_OPTS) -c $(EBPF_SRC_XDP) -o $(EBPF_OBJ_XDP)
$(EBPF_OBJ_TC_EGRESS): $(EBPF_SRC_TC_EGRESS)
	@mkdir -p $(@D)
	@echo "$(COLOUR_BLUE)[eBPF] Compiling: $< -> $@ $(END_COLOUR)"
	$(CLANG) $(CLANG_OPTS) -c $(EBPF_SRC_TC_EGRESS) -o $(EBPF_OBJ_TC_EGRESS)

clean_ebpf:
	@rm -f $(EBPF_OBJ_XDP) $(EBPF_OBJ_TC_EGRESS)
	@echo "$(COLOUR_GREEN)[Clean] Removed eBPF object file$(END_COLOUR)"

generate-version-and-build:
	@echo "$(COLOUR_BLUE)[OpenNHP] Start building... $(END_COLOUR)"
	@echo "$(COLOUR_BLUE)Version: ${VERSION} $(END_COLOUR)"
	@echo "$(COLOUR_BLUE)Commit id: ${COMMIT_ID} $(END_COLOUR)"
	@echo "$(COLOUR_BLUE)Commit time: ${COMMIT_TIME} $(END_COLOUR)"
	@echo "$(COLOUR_BLUE)Build time: ${BUILD_TIME} $(END_COLOUR)"
	@$(MAKE) init
	@$(MAKE) agentd
	@$(MAKE) acd
	@$(MAKE) serverd
	@$(MAKE) relayd
	@$(MAKE) db
	@$(MAKE) licenseadmin
	@$(MAKE) linuxagentsdk
	@$(MAKE) androidagentsdk
	@$(MAKE) macosagentsdk
	@$(MAKE) iosagentsdk
	@$(MAKE) devicesdk
	@$(MAKE) plugins
	@$(MAKE) archive
	@echo "$(COLOUR_GREEN)[OpenNHP] Build for platform ${OS_NAME} successfully done!$(END_COLOUR)"

init:
	@echo "$(COLOUR_BLUE)[OpenNHP] Initializing... $(END_COLOUR)"
	git clean -df release
	cd nhp && go mod tidy
	cd internalauth && go mod tidy
	cd endpoints && go mod tidy
	cd examples/server_plugin && go mod tidy
	cd tests/local && go mod tidy

agentd:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-agent... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-agent/nhp-agentd ./agent/main/main.go && \
	mkdir -p ../release/nhp-agent/etc && \
	cp ./agent/main/etc/*.toml ../release/nhp-agent/etc/

acd:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-ac... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-ac/nhp-acd ./ac/main/main.go && \
	cp ./ac/main/etc/*.toml ../release/nhp-ac/etc/

serverd:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-server... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-server/nhp-serverd ./server/main/main.go && \
	mkdir -p ../release/nhp-server/etc; \
	cp ./server/main/etc/*.toml ../release/nhp-server/etc/

relayd:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-relay... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-relay/nhp-relayd ./relay/main/main.go && \
	mkdir -p ../release/nhp-relay/etc; \
	cp ./relay/main/etc/*.toml ../release/nhp-relay/etc/

db:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-db... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-db/nhp-db ./db/main/main.go && \
	mkdir -p ../release/nhp-db/etc; \
	cp ./db/main/etc/*.toml ../release/nhp-db/etc/

licenseadmin:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-license-admin (license + F5 pubkey admin)... $(END_COLOUR)"
	cd endpoints && \
	mkdir -p ../release/nhp-license-admin && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-license-admin/nhp-license-admin ./licenseadmin/main/

linuxagentsdk:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building Linux agent SDK... $(END_COLOUR)"
ifeq ($(OS_NAME), linux)
	cd endpoints && \
	go build -a -trimpath -buildmode=c-shared -ldflags ${LD_FLAGS} -v -o ../release/nhp-agent/nhp-agent.so ./agent/main/main.go ./agent/main/export.go
endif

androidagentsdk:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building Android agent SDK... $(END_COLOUR)"
ifeq ($(OS_NAME), linux)
    ifeq ($(TOOLCHAIN),)
		@echo "Android NDK is not installed. Please install Android NDK to compile Android SDK."
    else
		cd endpoints && \
		GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
		CC=${ANDROID_CC} CXX=${ANDROID_CXX} \
		go build -a -trimpath -buildmode=c-shared -ldflags ${LD_FLAGS} -v -o ../release/nhp-agent/libnhpagent.so ./agent/main/main.go ./agent/main/export.go
    endif
endif


macosagentsdk:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building MacOS agent SDK... $(END_COLOUR)"
ifeq ($(OS_NAME), darwin)
ifeq (, $(shell test -f $(GOMOBILE) && echo found))
	$(error "No gomobile found, consider doing `go install golang.org/x/mobile/cmd/gomobile@latest`")
endif
	cd endpoints && \
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 \
	go build -a -trimpath -buildmode=c-shared -ldflags ${LD_FLAGS} -v -o ../release/nhp-agent/nhp-agent.dylib ./agent/main/main.go ./agent/main/export.go
endif

iosagentsdk:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building IOS agent SDK... $(END_COLOUR)"
ifeq ($(OS_NAME), darwin)
ifeq (, $(shell test -f $(GOMOBILE) && echo found))
	@echo "$(COLOUR_RED)[Warning] No gomobile found, skipping iOS SDK build$(END_COLOUR)"
	@echo "$(COLOUR_RED)Consider doing: go install golang.org/x/mobile/cmd/gomobile@latest$(END_COLOUR)"
else
ifeq (, $(XCODE_APP))
	@echo "$(COLOUR_RED)[Warning] Xcode is not installed, skipping iOS SDK build$(END_COLOUR)"
	@echo "$(COLOUR_RED)iOS SDK requires full Xcode installation (not just Command Line Tools)$(END_COLOUR)"
else
ifeq (, $(XCODE_SELECT))
	@echo "$(COLOUR_RED)[Warning] xcode-select is not pointing to Xcode.app, skipping iOS SDK build$(END_COLOUR)"
	@echo "$(COLOUR_RED)Please run: sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer$(END_COLOUR)"
else
	cd endpoints && \
	PATH=$(GOPATH)/bin:$$PATH $(GOMOBILE) bind -target ios -o ../release/nhp-agent/nhpagent.xcframework ./agent/iossdk
endif
endif
endif
endif


devicesdk:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp SDK... $(END_COLOUR)"
ifeq ($(OS_NAME), linux)
	cd nhp && \
	go build -a -trimpath -buildmode=c-shared -ldflags ${LD_FLAGS} -v -o ../release/nhp-device/nhpdevice.so ./core/main/main.go ./core/main/nhpdevice.go
#	gcc ./core/sdkdemo/nhp-device-demo.c -I ./release/nhp-device -I ./core/main -l:nhpdevice.so -L./release/nhp-device -Wl,-rpath=. -o ./release/nhp-device/nhp-device-demo
endif

plugins:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building plugins... $(END_COLOUR)"
	@if test -d $(NHP_SERVER_PLUGINS); then $(MAKE) -C $(NHP_SERVER_PLUGINS); fi

lint: lint-redirect-url-drift lint-qurl-link-og-image lint-disable-agent-validation lint-run-fuzz lint-ac-apt-guard lint-cis-metric-filter-patterns
	@echo "$(COLOUR_BLUE)[OpenNHP] Running linters...$(END_COLOUR)"
	cd nhp && golangci-lint run ./...
	cd internalauth && golangci-lint run ./...
	cd endpoints && golangci-lint run ./...
	@echo "$(COLOUR_GREEN)[OpenNHP] Lint passed!$(END_COLOUR)"

# Fence the generated qurl.link social preview PNG before deploy-time smoke.
# The SVG source uses editable text, so this checks the committed PNG's stable
# contract (dimensions + visible LayerV wordmark pixels) instead of re-rendering
# font-dependent text in CI.
.PHONY: lint-qurl-link-og-image
lint-qurl-link-og-image:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking qURL link social preview image...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-qurl-link-og-image.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./scripts/check-qurl-link-og-image.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] qURL link social preview image check passed!$(END_COLOUR)"

# Fence DisableAgentValidation=true from any deployable config (#1157 F9).
# The flag turns off agent static-pubkey validation entirely; setting
# it true in any prod path is a security regression that produces no
# runtime signal. The script is string-grep based so it stays runnable
# in a fresh CI image with no parser deps. Wired into `make lint` AND
# .github/workflows/validate-workflows.yml so a one-sided edit trips
# both locally and on PR.
.PHONY: lint-disable-agent-validation
lint-disable-agent-validation:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking DisableAgentValidation flag (#1157 F9)...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-disable-agent-validation.sh tests/lints/disable-agent-validation/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/disable-agent-validation/run-fixtures.sh
	@./scripts/check-disable-agent-validation.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] DisableAgentValidation check passed!$(END_COLOUR)"

# Fence drift between the `redirectURLField` constant in the plugin
# handler and the smoke test that verifies the wire contract (#1325).
# Wired into `make lint` so a one-sided rename trips locally before CI.
# CI runs the same script + fixtures in `redirect-url-drift-lint` in
# build-and-push.yml. The fixture suite runs first so a script regression
# (e.g., a regex tightening that drops a covered case) surfaces before
# the production paths are checked.
.PHONY: lint-redirect-url-drift
lint-redirect-url-drift:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking redirect_url drift (#1325)...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-redirect-url-drift.sh tests/lints/redirect-url-drift/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/redirect-url-drift/run-fixtures.sh
	@./scripts/check-redirect-url-drift.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] redirect_url drift check passed!$(END_COLOUR)"

# Fence the decision tree of scripts/run-fuzz.sh (#1653). The wrapper
# is the only thing distinguishing a real Go-fuzz crasher from the
# upstream coordinator deadline-race flake on the `fuzz-quick` job —
# a silent regression in it would re-introduce false-red on every PR
# OR mask a real crasher. The fixture suite emulates each go-test
# outcome via a PATH-shimmed `go` and asserts the wrapper's exit code.
.PHONY: lint-run-fuzz
lint-run-fuzz:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking run-fuzz wrapper (#1653)...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/run-fuzz.sh tests/lints/run-fuzz/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/run-fuzz/run-fixtures.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] run-fuzz wrapper check passed!$(END_COLOUR)"

# Fence AC user_data against boot-time apt update/install/upgrade regressions.
# Runtime dependencies must be baked by packer/nhp-ac.pkr.hcl and validated at
# boot, not installed from the public Ubuntu mirror in user_data.
.PHONY: lint-ac-apt-guard
lint-ac-apt-guard:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking AC boot-time apt guard...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck tests/lints/ac-apt-guard/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/ac-apt-guard/run-fixtures.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] AC boot-time apt guard passed!$(END_COLOUR)"

# Freeze the CIS v1.4.0 CloudWatch metric-filter patterns in
# terraform/modules/security/cloudtrail_metric_filters.tf against the golden
# in tests/lints/cis-metric-filter-patterns/golden.json (#1140 / PR #2344).
# Security Hub matches these verbatim; an accidental edit silently FAILS the
# CloudWatch.N control ~18h after the prod apply (sandbox has no trail to
# pre-validate against). Fixtures run first so a checker regression surfaces
# before the production check. CI runs the same in build-and-push.yml's
# terraform-prod-drift-lint job (PR-gated).
.PHONY: lint-cis-metric-filter-patterns
lint-cis-metric-filter-patterns:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking CIS metric-filter patterns (#1140)...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck tests/lints/cis-metric-filter-patterns/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/cis-metric-filter-patterns/run-fixtures.sh
	@python3 ./.github/scripts/check-cis-metric-filter-patterns.py
	@echo "$(COLOUR_GREEN)[OpenNHP] CIS metric-filter pattern check passed!$(END_COLOUR)"

# Run the same checks CI runs for .github/workflows/**,
# .github/ISSUE_TEMPLATE/**, and CLAUDE.md's Scopes table.
# CI splits these across two workflows:
#   - validate-workflows.yml       → actionlint + shellcheck + scope-drift
#   - validate-issue-templates.yml → shim to ops-routines-workflows reusable
# `make lint-workflows` runs the equivalent of both locally.
# Requires actionlint, shellcheck, check-jsonschema, and python3+PyYAML
# on PATH:
#   macOS:  brew install actionlint shellcheck && pipx install 'check-jsonschema==0.37.1'
#           && python3 -m pip install pyyaml
#   Linux:  see https://github.com/rhysd/actionlint#install,
#           your distro's shellcheck + python3-yaml packages, and
#           `pipx install 'check-jsonschema==0.37.1'` (or `pip install --user`)
# NB: check-jsonschema version is pinned in lockstep with the reusable
# (layervai/ops-routines-workflows validate-issue-templates.yml); the
# script will fail loud on version mismatch. Bump alongside the reusable.
# Bump sites (keep in sync):
#   1. scripts/lint-issue-templates.sh  CHECK_JSONSCHEMA_VERSION
#   2. Makefile (this block)            two `pipx install` hints above
#   3. Makefile                         `command -v` error message below
#   4. The reusable's default input     ops-routines-workflows .github/…
# Fails on any finding — quote every variable, fix or explicitly
# suppress shellcheck warnings. Matches `validate-workflows.yml` exactly
# so "passes locally" == "passes in CI".
.PHONY: lint-workflows
lint-workflows:
	@echo "$(COLOUR_BLUE)[OpenNHP] Linting GitHub Actions workflows...$(END_COLOUR)"
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] actionlint not found. Install: brew install actionlint (macOS) or https://github.com/rhysd/actionlint#install (Linux)$(END_COLOUR)"; \
		exit 1; \
	}
	@command -v shellcheck >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] shellcheck not found. Install: brew install shellcheck (macOS) or apt install shellcheck (Debian/Ubuntu)$(END_COLOUR)"; \
		exit 1; \
	}
	@command -v check-jsonschema >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] check-jsonschema not found. Install: pipx install 'check-jsonschema==0.37.1' (version pinned to match the ops-routines reusable)$(END_COLOUR)"; \
		exit 1; \
	}
	@actionlint -color -shellcheck "$$(command -v shellcheck)" .github/workflows/*.yml
	@bash scripts/lint-issue-templates.sh
	@bash tests/scripts/check-scope-drift_test.sh
	@bash scripts/check-scope-drift.sh
	@bash tests/scripts/check-go-version-drift_test.sh
	@bash scripts/check-go-version-drift.sh
	@bash scripts/check-smoke-tier-filter-coverage.sh
	@bash scripts/check-cert-cleanup-log-gate-unique.sh
	@bash scripts/check-cleanup-event-type-lockstep.sh
	@shellcheck scripts/check-golden-vectors.sh tests/scripts/check-golden-vectors_test.sh
	@bash tests/scripts/check-golden-vectors_test.sh
	@bash scripts/check-golden-vectors.sh
	@bash scripts/check-lockdown-body-drift.sh
	@bash scripts/check-frps-az-suffixes-validation-drift.sh
	@bash tests/lints/nhp-server-internal-url-validation-drift/run-fixtures.sh
	@bash scripts/check-nhp-server-internal-url-validation-drift.sh
	@bash tests/scripts/check-image-tag-writer-allowlist_test.sh
	@shellcheck .github/scripts/deploy-relay.sh tests/scripts/deploy-relay_test.sh
	@bash tests/scripts/deploy-relay_test.sh
	@shellcheck .github/scripts/resolve-active-image-tag.sh tests/scripts/resolve-active-image-tag_test.sh
	@bash tests/scripts/resolve-active-image-tag_test.sh
	@shellcheck .github/scripts/plan-blue-green-dispatch.sh tests/scripts/plan-blue-green-dispatch_test.sh
	@bash tests/scripts/plan-blue-green-dispatch_test.sh
	@shellcheck scripts/check-app-image-line-rendered.sh tests/scripts/check-app-image-line-rendered_test.sh
	@bash tests/scripts/check-app-image-line-rendered_test.sh
	@bash tests/scripts/ami-id-from-manifest_test.sh
	@shellcheck .github/scripts/classify-terraform-plan-pr-changes.sh tests/scripts/classify-terraform-plan-pr-changes_test.sh
	@bash tests/scripts/classify-terraform-plan-pr-changes_test.sh
	@python3 tests/scripts/test_summarize_terraform_plan.py
	@python3 -c 'import yaml' 2>/dev/null || { \
		echo "$(COLOUR_RED)[OpenNHP] PyYAML missing.$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  Match the CI install: python3 -m pip install --no-cache-dir pyyaml$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  (See .github/workflows/validate-workflows.yml's 'Install PyYAML' step.)$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  Most laptops also need --user, --break-system-packages, or a venv depending on python install.$(END_COLOUR)"; \
		exit 1; \
	}
	@python3 tests/scripts/test_promote_to_prod_gating.py
	@bash tests/scripts/check-sandbox-qurl-roll_test.sh
	@shellcheck .github/scripts/deploy-ecs-service.sh tests/scripts/deploy-ecs-service_test.sh
	@bash tests/scripts/deploy-ecs-service_test.sh
	@bash tests/scripts/dependabot-go-tidy_test.sh
	@bash tests/lints/paths-filter-coverage/run-fixtures.sh
	@python3 scripts/check-paths-filter-coverage.py
	@bash tests/lints/dispatch-ref-error/run-fixtures.sh
	@shellcheck tests/lints/verify-image-attestation/run-fixtures.sh
	@bash tests/lints/verify-image-attestation/run-fixtures.sh
	@shellcheck .github/scripts/scan-attestation-soak.sh tests/lints/attestation-verify-watchdog/run-fixtures.sh
	@bash tests/lints/attestation-verify-watchdog/run-fixtures.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] Workflow lint passed!$(END_COLOUR)"

# Run the terraform-prod-drift detectors (#1324). Static, AWS-creds-free
# lints that fence the regression classes from #1316 and #1323. CI runs
# the same scripts in the dedicated `terraform-prod-drift-lint` job in
# build-and-push.yml.
# Requires python-hcl2 — install via:
#   python3 -m pip install -r .github/scripts/terraform-prod-drift-requirements.txt
# Mirrors the CI step's install (same pinned version).
.PHONY: lint-terraform-drift
lint-terraform-drift:
	@echo "$(COLOUR_BLUE)[OpenNHP] Running terraform-prod-drift detectors (#1324)...$(END_COLOUR)"
	@python3 -c 'import hcl2' >/dev/null || { \
		echo "$(COLOUR_RED)[OpenNHP] python-hcl2 missing. Install: python3 -m pip install -r .github/scripts/terraform-prod-drift-requirements.txt$(END_COLOUR)"; \
		exit 1; \
	}
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck tests/lints/terraform-prod-drift/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping run-fixtures.sh check$(END_COLOUR)"; \
	fi
	@./tests/lints/terraform-prod-drift/run-fixtures.sh
	@python3 .github/scripts/check-terraform-iam-coverage.py
	@python3 .github/scripts/check-terraform-policy-conditions.py
	@python3 tests/scripts/test_check_terraform_plan_pr_policy_readonly.py
	@python3 .github/scripts/check-terraform-plan-pr-policy-readonly.py
	@./tests/lints/terraform-tag-charset/run-fixtures.sh
	@python3 .github/scripts/check-terraform-tag-charset.py terraform
	@./tests/lints/asg-capacity-deficit-alarms/run-fixtures.sh
	@python3 .github/scripts/check-asg-capacity-deficit-alarms.py
	@python3 tests/scripts/test_observability_parity.py
	@python3 scripts/check-observability-parity.py
	@echo "$(COLOUR_GREEN)[OpenNHP] terraform drift and alarm-shape checks passed!$(END_COLOUR)"

test:
	@echo "[OpenNHP] Running Unit Tests..."
	cd internalauth && go test -v ./... -race
	cd endpoints && KBS_SKIP_INIT=1 go test -v ./server/... -run "Test.*ACPeers|TestEmptyVsNil|TestEtcd|TestMerged|TestParse|TestACRegistry"
	@echo "$(COLOUR_GREEN)[OpenNHP] Unit Tests Done!$(END_COLOUR)"

test-lambdas: ## Run Lambda unit tests (Python)
	@echo "[OpenNHP] Running Lambda Unit Tests..."
	python3 -m pytest terraform/modules/billing/lambda/test_*.py terraform/modules/developer-portal/lambda/test_*.py -v
	@echo "$(COLOUR_GREEN)[OpenNHP] Lambda Unit Tests Done!$(END_COLOUR)"

test-local: ## Run local e2e tests (requires: docker compose -f tests/local/docker-compose.test.yaml up -d etcd)
	@echo "[OpenNHP] Running Local E2E Tests..."
	cd tests/local && go test -v -tags=local ./...
	@echo "$(COLOUR_GREEN)[OpenNHP] Local E2E Tests Done!$(END_COLOUR)"

# Smoke tests run against a LIVE environment. See tests/smoke/doc.go
# for the full environment variable matrix and tests/smoke/README (if
# added) for the capability map.
#
# test-smoke-sandbox uses AWS_PROFILE=layerv and fetches Auth0
# credentials from Secrets Manager. Requires AWS CLI + jq installed.
test-smoke-sandbox: ## Run smoke tests against sandbox (uses AWS_PROFILE=layerv)
	@echo "[OpenNHP] Running smoke tests against sandbox..."
	@command -v jq >/dev/null 2>&1 || { echo "$(COLOUR_RED)[OpenNHP] jq not found — install with: brew install jq$(END_COLOUR)"; exit 1; }
	@SECRET=$$(AWS_PROFILE=layerv aws secretsmanager get-secret-value \
		--secret-id "layerv-nhp-sandbox-auth0-smoke-test-credentials" \
		--query SecretString --output text) && \
	cd tests/smoke && \
	NHP_ENVIRONMENT=sandbox \
	NHP_SMOKE_ALLOW_SSM_PROBES=true \
	AWS_PROFILE=layerv \
	AWS_REGION=us-east-2 \
	AUTH0_CLIENT_ID=$$(echo "$$SECRET" | jq -r '.client_id') \
	AUTH0_CLIENT_SECRET=$$(echo "$$SECRET" | jq -r '.client_secret') \
	AUTH0_DOMAIN=auth.layerv.ai \
	AUTH0_AUDIENCE=https://api.layerv.xyz \
	go test -tags=smoke -v -count=1 -timeout 15m ./...
	@echo "$(COLOUR_GREEN)[OpenNHP] Sandbox smoke tests done!$(END_COLOUR)"

# test-smoke-prod uses AWS_PROFILE=layerv-prod. SSM probes are OFF by
# default during the 30-day burn-in; pass NHP_SMOKE_ALLOW_SSM_PROBES=true
# on the command line to override.
test-smoke-prod: ## Run smoke tests against prod (uses AWS_PROFILE=layerv-prod)
	@echo "[OpenNHP] Running smoke tests against PROD..."
	@command -v jq >/dev/null 2>&1 || { echo "$(COLOUR_RED)[OpenNHP] jq not found — install with: brew install jq$(END_COLOUR)"; exit 1; }
	@SECRET=$$(AWS_PROFILE=layerv-prod aws secretsmanager get-secret-value \
		--secret-id "layerv-nhp-prod-auth0-smoke-test-credentials" \
		--region us-east-2 \
		--query SecretString --output text) && \
	cd tests/smoke && \
	NHP_ENVIRONMENT=prod \
	NHP_SMOKE_ALLOW_SSM_PROBES=$${NHP_SMOKE_ALLOW_SSM_PROBES:-false} \
	AWS_PROFILE=layerv-prod \
	AWS_REGION=us-east-2 \
	AUTH0_CLIENT_ID=$$(echo "$$SECRET" | jq -r '.client_id') \
	AUTH0_CLIENT_SECRET=$$(echo "$$SECRET" | jq -r '.client_secret') \
	AUTH0_DOMAIN=auth.layerv.ai \
	AUTH0_AUDIENCE=https://api.layerv.ai \
	go test -tags=smoke -v -count=1 -timeout 15m ./...
	@echo "$(COLOUR_GREEN)[OpenNHP] Prod smoke tests done!$(END_COLOUR)"

test-debug: ## Run the #2214 pointer-uniqueness fence under -tags=nhp_debug (the CI fence; opts in to the panic-on-reuse variant of common.TokenStore.Store)
	@echo "[OpenNHP] Running #2214 pointer-uniqueness fence under -tags=nhp_debug..."
	cd nhp && go test -tags=nhp_debug -count=1 -race -timeout 2m ./common/...
	cd endpoints && KBS_SKIP_INIT=1 go test -tags=nhp_debug -count=1 -race -timeout 5m ./ac/... ./server/...
	@echo "$(COLOUR_GREEN)[OpenNHP] Debug-tag fence tests done!$(END_COLOUR)"

test-all: test test-lambdas test-local ## Run all tests

# Fuzz parameters. The fuzz recipes route through scripts/run-fuzz.sh,
# which distinguishes a real crasher (writes testdata/fuzz/<NAME>/<sha>)
# from the upstream Go-fuzz coordinator deadline-race flake (no
# reproducer file). Prior history: nhp#1188 / qurl-service#325 papered
# over the race by raising FUZZTIME_QUICK from 10s to 15s; nhp#1649
# tripped it again, which is what motivated the structural workaround.
# Override FUZZTIME_QUICK / FUZZTIME_LONG for longer nightly runs.
FUZZTIME_QUICK ?= 15s
FUZZTIME_LONG  ?= 60s

# Single source of truth for the fuzz target list — `fuzz` and
# `fuzz-quick` both iterate this. Adding a new fuzzer is one line here,
# not one line in each recipe (the latter is how nhp#1175 happened).
FUZZ_TARGETS := \
	FuzzECDHFromKey \
	FuzzHeaderTypeToDeviceType \
	FuzzHeaderTypeAndSize \
	FuzzAgentKnockMsg \
	FuzzServerKnockAckMsg \
	FuzzACOpsResultMsg \
	FuzzDARMsg

# Endpoints-side fuzz targets (live in endpoints/server/, need
# KBS_SKIP_INIT=1 to avoid the private-key init path firing during
# test binary startup).
FUZZ_TARGETS_ENDPOINTS := \
	FuzzHttpKnockForwardRequest \
	FuzzHttpKnockRequest \
	FuzzHandleInternalKnockBypass

# Run fuzz tests (full budget per target, for nightly / manual runs).
# -run='^$$' skips every Test* in nhp/test/ so the fuzz runner only does
# fuzz work — the regular tests are already covered by `make test` in
# the build job, and a flaky unit test in that package would otherwise
# flip this target red for reasons unrelated to fuzzing.
fuzz:
	@echo "$(COLOUR_BLUE)[OpenNHP] Running fuzz tests (fuzztime=$(FUZZTIME_LONG))...$(END_COLOUR)"
	@cd nhp && for t in $(FUZZ_TARGETS); do \
		echo "[OpenNHP]   -> $$t"; \
		../scripts/run-fuzz.sh ./test/ $$t $(FUZZTIME_LONG) || exit $$?; \
	done
	@echo "[OpenNHP]   -> FuzzNewVerifier"
	@cd nhp && ../scripts/run-fuzz.sh ./core/verifier/ FuzzNewVerifier $(FUZZTIME_LONG)
	@cd endpoints && for t in $(FUZZ_TARGETS_ENDPOINTS); do \
		echo "[OpenNHP]   -> $$t"; \
		KBS_SKIP_INIT=1 ../scripts/run-fuzz.sh ./server/ $$t $(FUZZTIME_LONG) || exit $$?; \
	done
	@echo "[OpenNHP]   -> FuzzAccessTokenValidationDifferential"
	@cd endpoints && KBS_SKIP_INIT=1 ../scripts/run-fuzz.sh ./server/staticplugins/qurl/ FuzzAccessTokenValidationDifferential $(FUZZTIME_LONG)
	@echo "$(COLOUR_GREEN)[OpenNHP] Fuzz tests completed$(END_COLOUR)"

# Run fuzz tests at a shortened budget (CI default; see fuzz: above for
# the -run='^$$' rationale).
fuzz-quick:
	@echo "$(COLOUR_BLUE)[OpenNHP] Running quick fuzz tests (fuzztime=$(FUZZTIME_QUICK))...$(END_COLOUR)"
	@cd nhp && for t in $(FUZZ_TARGETS); do \
		echo "[OpenNHP]   -> $$t"; \
		../scripts/run-fuzz.sh ./test/ $$t $(FUZZTIME_QUICK) || exit $$?; \
	done
	@echo "[OpenNHP]   -> FuzzNewVerifier"
	@cd nhp && ../scripts/run-fuzz.sh ./core/verifier/ FuzzNewVerifier $(FUZZTIME_QUICK)
	@cd endpoints && for t in $(FUZZ_TARGETS_ENDPOINTS); do \
		echo "[OpenNHP]   -> $$t"; \
		KBS_SKIP_INIT=1 ../scripts/run-fuzz.sh ./server/ $$t $(FUZZTIME_QUICK) || exit $$?; \
	done
	@echo "[OpenNHP]   -> FuzzAccessTokenValidationDifferential"
	@cd endpoints && KBS_SKIP_INIT=1 ../scripts/run-fuzz.sh ./server/staticplugins/qurl/ FuzzAccessTokenValidationDifferential $(FUZZTIME_QUICK)
	@echo "$(COLOUR_GREEN)[OpenNHP] Quick fuzz tests completed$(END_COLOUR)"

archive:
	@echo "$(COLOUR_BLUE)[OpenNHP] Start archiving... $(END_COLOUR)"
	@cd release && mkdir -p archive && tar -czvf ./archive/$(PACKAGE_FILE) nhp-agent nhp-ac nhp-db nhp-server nhp-relay
	@echo "$(COLOUR_GREEN)[OpenNHP] Package ${PACKAGE_FILE} archived!$(END_COLOUR)"

.PHONY: all generate-version-and-build init agentd acd serverd relayd db licenseadmin linuxagentsdk androidagentsdk macosagentsdk iosagentsdk devicesdk plugins lint test test-lambdas test-local test-smoke-sandbox test-smoke-prod test-all fuzz fuzz-quick archive ebpf clean_ebpf
