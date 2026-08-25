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
# The clang guard fires for any goal whose name contains "ebpf"
# (both `ebpf` and `ebpf-objects`), so clang/llvm is required only
# when an eBPF compile is actually requested — never for the plain
# server/relay/agent builds (`make`, `make acd`, etc.). Keep "ebpf"
# in any new eBPF target name, or extend this findstring, or the
# guard silently stops protecting it.
ifneq (,$(findstring ebpf,$(MAKECMDGOALS)))
    CLANG ?= $(shell command -v clang 2>/dev/null)
    # Keep env/CLI CLANG=<binary> overrides, then flatten the fallback so
    # `command -v clang` is not re-run on every $(CLANG) reference below.
    CLANG := $(CLANG)
    ifeq ($(CLANG),)
        $(error "clang is not installed. Please install clang or run with CLANG=<clang binary> to compile eBPF programs.")
    endif
    ifeq ($(shell command -v $(CLANG) 2>/dev/null),)
        $(error "CLANG=$(CLANG) was not found. Pass CLANG=<clang binary> or install clang to compile eBPF programs.")
    endif
endif

EBPF_SRC_XDP = ./nhp/ebpf/xdp/nhp_ebpf_xdp.c
EBPF_SRC_TC_EGRESS = ./nhp/ebpf/xdp/tc_egress.c
EBPF_OBJ_XDP = ./release/nhp-ac/etc/nhp_ebpf_xdp.o
EBPF_OBJ_TC_EGRESS = ./release/nhp-ac/etc/tc_egress.o
# Both sources #include "vmlinux.h" (the in-tree, BTF-generated kernel
# type header). It's a prerequisite so a local incremental `make
# ebpf-objects` after a vmlinux.h regen recompiles instead of shipping a
# stale object. The other includes (<bpf/bpf_helpers.h> etc.) are libbpf
# system headers, not in-tree, so they can't be Make prerequisites — the
# Docker build always does a clean compile, so they're not a staleness
# risk there.
EBPF_VMLINUX_H = ./nhp/ebpf/xdp/vmlinux.h
# Keep BTF paths reproducible so the committed-object freshness gate can compare
# byte-for-byte across local containers and GitHub runner workspaces.
# Do not switch eBPF source paths or include paths to absolute forms without
# extending this prefix map; the committed native AC object is DWARF-stripped,
# but .BTF/.BTF.ext survives debug stripping and can otherwise make the
# required load-relevant comparison workspace-dependent.
CLANG_PREFIX_MAP = -ffile-prefix-map=$(CURDIR)=.
CLANG_OPTS = -O2 -target bpf -g -Wall -I. $(CLANG_PREFIX_MAP)

# ebpf-objects compiles ONLY the two eBPF object files into
# ./release/nhp-ac/etc/ (the path the AC loads from — source of truth is
# endpoints/ac/ebpf/ebpfegine.go). This is the target the AC Docker image
# build uses (docker/Dockerfile.ac.aws). Deliberately decoupled from
# `generate-version-and-build`: the AC image only needs the objects, not
# the full multi-binary build/SDK/archive pipeline the legacy `ebpf`
# target pulls in.
.PHONY: ebpf-objects
ebpf-objects: $(EBPF_OBJ_XDP) $(EBPF_OBJ_TC_EGRESS)
	@echo "$(COLOUR_GREEN)[eBPF] Object files compiled$(END_COLOUR)"

.PHONY: ebpf
ebpf: ebpf-objects generate-version-and-build
	@echo "$(COLOUR_GREEN)[eBPF] Full build completed$(END_COLOUR)"

$(EBPF_OBJ_XDP): $(EBPF_SRC_XDP) $(EBPF_VMLINUX_H)
	@mkdir -p $(@D)
	@echo "$(COLOUR_BLUE)[eBPF] Compiling: $< -> $@ $(END_COLOUR)"
	$(CLANG) $(CLANG_OPTS) -c $(EBPF_SRC_XDP) -o $(EBPF_OBJ_XDP)
$(EBPF_OBJ_TC_EGRESS): $(EBPF_SRC_TC_EGRESS) $(EBPF_VMLINUX_H)
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
	@$(MAKE) hubd
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
	cd tests/e2e && go mod tidy

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
	mkdir -p ../release/nhp-ac/etc && \
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

hubd:
	@echo "$(COLOUR_BLUE)[OpenNHP] Building nhp-hub... $(END_COLOUR)"
	cd endpoints && \
	go build -trimpath -ldflags ${LD_FLAGS} -v -o ../release/nhp-hub/nhp-hubd ./server/hub/main/main.go && \
	mkdir -p ../release/nhp-hub/etc && \
	cp ./server/hub/main/etc/*.toml ../release/nhp-hub/etc/

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

lint: lint-qurl-csp-gate-drift lint-qurl-link-og-image lint-disable-agent-validation lint-errorcode-to-error-callers lint-run-fuzz lint-ac-apt-guard lint-ubuntu-apt-mirror-fallback lint-cis-metric-filter-patterns lint-dispatch-concurrency-isolation lint-prod-deploy-relay-activation
	@echo "$(COLOUR_BLUE)[OpenNHP] Running linters...$(END_COLOUR)"
	cd nhp && golangci-lint run ./...
	cd internalauth && golangci-lint run ./...
	cd endpoints && golangci-lint run ./...
	# Keep this build-tag set in lockstep with the ubuntu-build.yml lint matrix.
	cd tests/e2e && golangci-lint run --build-tags=e2e ./...
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

# Enforces the ErrorCodeToError invariant that docs/UPSTREAM_SYNC.md records
# (PR #3643). Deliberately a lint and not a Go test: a repo-walking Go test is
# subject to Go's test-result cache, which returned a cached PASS after a fresh
# offending file was added — a fence that passes exactly when it should fail.
.PHONY: lint-errorcode-to-error-callers
lint-errorcode-to-error-callers:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking ErrorCodeToError callers (PR #3643)...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-errorcode-to-error-callers.sh tests/lints/errorcode-to-error-callers/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/errorcode-to-error-callers/run-fixtures.sh
	@./scripts/check-errorcode-to-error-callers.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] ErrorCodeToError caller check passed!$(END_COLOUR)"

# Fence qurl.link CSP propagation wait drift from the smoke assertion it is
# trying to de-flake. Wired into `make lint` so local runs catch a one-sided
# workflow/smoke/tfvar/origin edit before CI.
# CI runs the same script + fixtures in `qurl-csp-gate-drift-lint` in
# build-and-push.yml.
.PHONY: lint-qurl-csp-gate-drift
lint-qurl-csp-gate-drift:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking qurl.link CSP gate drift...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-qurl-csp-gate-drift.sh scripts/parse-qurl-csp-probe-output.sh tests/lints/qurl-csp-gate-drift/run-fixtures.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@./tests/lints/qurl-csp-gate-drift/run-fixtures.sh
	@./scripts/check-qurl-csp-gate-drift.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] qurl.link CSP gate drift check passed!$(END_COLOUR)"

# Fence the decision tree of scripts/run-fuzz.sh (#1653). The wrapper
# is the only thing distinguishing a real Go-fuzz crasher from the
# upstream coordinator deadline-race flake on the `fuzz-quick` job —
# a silent regression in it would re-introduce false-red on every PR
# OR mask a real crasher. The fixture suite emulates each go-test
# outcome via a PATH-shimmed `go` and asserts the wrapper's exit code.
.PHONY: lint-run-fuzz
# A build-and-push dispatch carrying a correlation_id has a parent pipeline
# blocking on it, so an unrelated ad-hoc deploy must not be able to cancel it.
lint-dispatch-concurrency-isolation:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking dispatch concurrency isolation...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/check-dispatch-concurrency-isolation.sh tests/scripts/check-dispatch-concurrency-isolation_test.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@bash tests/scripts/check-dispatch-concurrency-isolation_test.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] dispatch concurrency isolation check passed!$(END_COLOUR)"

lint-prod-deploy-relay-activation:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking prod-deploy relay activation detection...$(END_COLOUR)"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/trigger-prod-deploy.sh tests/scripts/trigger-prod-deploy-relay-activation_test.sh; \
	else \
		echo "$(COLOUR_BLUE)[OpenNHP] shellcheck not installed; skipping script check$(END_COLOUR)"; \
	fi
	@bash tests/scripts/trigger-prod-deploy-relay-activation_test.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] prod-deploy relay activation check passed!$(END_COLOUR)"

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

# Keep every application-image matrix runtime on one bounded package-index
# strategy: pinned official sources first, Azure-local fallback, then fail.
.PHONY: lint-ubuntu-apt-mirror-fallback
lint-ubuntu-apt-mirror-fallback:
	@echo "$(COLOUR_BLUE)[OpenNHP] Checking Ubuntu apt mirror fallback...$(END_COLOUR)"
	@shellcheck docker/ubuntu-apt-install-with-fallback.sh scripts/check-ubuntu-apt-mirror-fallback.sh tests/lints/ubuntu-apt-mirror-fallback/run-fixtures.sh
	@./tests/lints/ubuntu-apt-mirror-fallback/run-fixtures.sh
	@./scripts/check-ubuntu-apt-mirror-fallback.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] Ubuntu apt mirror fallback passed!$(END_COLOUR)"

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
# Requires actionlint, shellcheck, check-jsonschema, Go, Node.js, and Python
# 3.10+ with the pinned lint dependencies from
# .github/scripts/validate-workflows-requirements.txt (PyYAML + the jsonschema
# LIBRARY, which is not the same thing as the check-jsonschema CLI below)
# on PATH:
#   macOS:  brew install actionlint shellcheck go node && pipx install 'check-jsonschema==0.37.1'
#           && python3 -m pip install -r .github/scripts/validate-workflows-requirements.txt
#   Linux:  see https://github.com/rhysd/actionlint#install,
#           your distro's shellcheck + Go + Node.js packages,
#           `pipx install 'check-jsonschema==0.37.1'` (or `pip install --user`), and
#           `python3 -m pip install -r .github/scripts/validate-workflows-requirements.txt`
# Both Python deps are proved in ONE preflight next to the other tool checks.
# jsonschema used to be checked ~145 recipe lines in, so a machine that had
# PyYAML but not jsonschema ran actionlint, two terraform module test suites,
# the node suites and dozens of Python/bash fences before failing on a missing
# import -- minutes of work to deliver an install hint. Add any new dep to the
# requirements file AND that preflight, never to a check further down.
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
	@command -v go >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] go not found. Install the Go toolchain pinned by endpoints/go.mod to run relay dependency lockstep tests$(END_COLOUR)"; \
		exit 1; \
	}
	@command -v python3 >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] python3 not found. Install Python 3.10 or newer to run workflow contract checks$(END_COLOUR)"; \
		exit 1; \
	}
	@python3 -c 'import sys; sys.version_info >= (3, 10) or sys.exit("[OpenNHP] Python 3.10 or newer is required for workflow contract checks")'
	@# Every pinned dep, up front. Keep in lockstep with the requirements file.
	@python3 -c 'import jsonschema, yaml' 2>/dev/null || { \
		echo "$(COLOUR_RED)[OpenNHP] lint-workflows needs the pinned Python deps (PyYAML + jsonschema).$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  Match the CI install: python3 -m pip install --no-cache-dir -r .github/scripts/validate-workflows-requirements.txt$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  (See .github/workflows/validate-workflows.yml's 'Install lint dependencies' step.)$(END_COLOUR)"; \
		echo "$(COLOUR_RED)  Most laptops also need --user, --break-system-packages, or a venv depending on python install.$(END_COLOUR)"; \
		exit 1; \
	}
	@actionlint -color -shellcheck "$$(command -v shellcheck)" .github/workflows/*.yml
	@python3 tests/scripts/test_check_claude_model_lockstep.py
	@python3 scripts/check-claude-model-lockstep.py
	@bash scripts/lint-issue-templates.sh
	@bash tests/scripts/check-scope-drift_test.sh
	@bash scripts/check-scope-drift.sh
	@bash tests/scripts/check-go-version-drift_test.sh
	@bash scripts/check-go-version-drift.sh
	@shellcheck scripts/check-traefik-grpc-pin.sh tests/scripts/check-traefik-grpc-pin_test.sh
	@bash tests/scripts/check-traefik-grpc-pin_test.sh
	@bash scripts/check-traefik-grpc-pin.sh
	@shellcheck scripts/check-smoke-tier-filter-coverage.sh tests/lints/smoke-tier-filter-coverage/run-fixtures.sh
	@bash tests/lints/smoke-tier-filter-coverage/run-fixtures.sh
	@bash scripts/check-smoke-tier-filter-coverage.sh
	@bash scripts/check-cert-cleanup-log-gate-unique.sh
	@bash scripts/check-cleanup-event-type-lockstep.sh
	@shellcheck scripts/check-base-image-pebble-purge.sh tests/scripts/check-base-image-pebble-purge_test.sh
	@bash tests/scripts/check-base-image-pebble-purge_test.sh
	@bash scripts/check-base-image-pebble-purge.sh
	@shellcheck scripts/check-ubuntu-base-digest-drift.sh tests/scripts/check-ubuntu-base-digest-drift_test.sh
	@bash tests/scripts/check-ubuntu-base-digest-drift_test.sh
	@bash scripts/check-ubuntu-base-digest-drift.sh
	@shellcheck docker/ubuntu-apt-install-with-fallback.sh scripts/check-ubuntu-apt-mirror-fallback.sh tests/lints/ubuntu-apt-mirror-fallback/run-fixtures.sh
	@bash tests/lints/ubuntu-apt-mirror-fallback/run-fixtures.sh
	@bash scripts/check-ubuntu-apt-mirror-fallback.sh
	@shellcheck scripts/check-lambda-boto-pin-lockstep.sh tests/scripts/check-lambda-boto-pin-lockstep_test.sh
	@bash tests/scripts/check-lambda-boto-pin-lockstep_test.sh
	@bash scripts/check-lambda-boto-pin-lockstep.sh
	@shellcheck scripts/check-ac-user-data-heredoc-backticks.sh tests/scripts/check-ac-user-data-heredoc-backticks_test.sh
	@bash tests/scripts/check-ac-user-data-heredoc-backticks_test.sh
	@bash scripts/check-ac-user-data-heredoc-backticks.sh
	@shellcheck scripts/check-revocation-slo-lockstep.sh tests/scripts/check-revocation-slo-lockstep_test.sh
	@bash tests/scripts/check-revocation-slo-lockstep_test.sh
	@bash scripts/check-revocation-slo-lockstep.sh
	@shellcheck scripts/check-l3-conntrack-pool-lockstep.sh tests/scripts/check-l3-conntrack-pool-lockstep_test.sh
	@bash tests/scripts/check-l3-conntrack-pool-lockstep_test.sh
	@bash scripts/check-l3-conntrack-pool-lockstep.sh
	@shellcheck scripts/check-ebpf-load-path-lockstep.sh tests/scripts/check-ebpf-load-path-lockstep_test.sh
	@bash tests/scripts/check-ebpf-load-path-lockstep_test.sh
	@bash scripts/check-ebpf-load-path-lockstep.sh
	@shellcheck tests/lints/ebpf-load-path-lockstep/run-fixtures.sh
	@bash tests/lints/ebpf-load-path-lockstep/run-fixtures.sh
	@shellcheck scripts/check-ac-ebpf-arch-lockstep.sh tests/scripts/check-ac-ebpf-arch-lockstep_test.sh
	@bash tests/scripts/check-ac-ebpf-arch-lockstep_test.sh
	@bash scripts/check-ac-ebpf-arch-lockstep.sh
	@shellcheck scripts/check-ebpf-toolchain-pin-lockstep.sh tests/scripts/check-ebpf-toolchain-pin-lockstep_test.sh scripts/install-ebpf-toolchain.sh tests/scripts/install-ebpf-toolchain_test.sh scripts/check-ebpf-committed-object-drift.sh tests/scripts/check-ebpf-committed-object-drift_test.sh
	@bash tests/scripts/check-ebpf-toolchain-pin-lockstep_test.sh
	@bash scripts/check-ebpf-toolchain-pin-lockstep.sh
	@bash tests/scripts/install-ebpf-toolchain_test.sh
	@bash tests/scripts/check-ebpf-committed-object-drift_test.sh
	@shellcheck scripts/check-golden-vectors.sh tests/scripts/check-golden-vectors_test.sh
	@bash tests/scripts/check-golden-vectors_test.sh
	@bash scripts/check-golden-vectors.sh
	@shellcheck scripts/check-conformance-parity.sh tests/scripts/check-conformance-parity_test.sh
	@bash tests/scripts/check-conformance-parity_test.sh
	@shellcheck scripts/check-agent-reg-vector-drift.sh tests/scripts/check-agent-reg-vector-drift_test.sh
	@bash tests/scripts/check-agent-reg-vector-drift_test.sh
	@shellcheck scripts/check-hub-lst-kat-drift.sh tests/scripts/check-hub-lst-kat-drift_test.sh
	@bash tests/scripts/check-hub-lst-kat-drift_test.sh
	@shellcheck tests/scripts/check-hub-image-contract.sh
	@bash scripts/check-lockdown-body-drift.sh
	@bash scripts/check-frps-az-suffixes-validation-drift.sh
	@bash tests/lints/nhp-server-internal-url-validation-drift/run-fixtures.sh
	@bash scripts/check-nhp-server-internal-url-validation-drift.sh
	@bash tests/scripts/check-image-tag-writer-allowlist_test.sh
	@shellcheck .github/scripts/wait-for-instance-refresh.sh .github/scripts/deploy-relay.sh .github/scripts/dispatch-and-poll-blue-green.sh .github/scripts/dispatch-and-poll-canary.sh .github/scripts/emit-deployment-window-metric.sh tests/scripts/wait-for-instance-refresh_test.sh tests/scripts/deploy-relay_test.sh tests/scripts/emit-deployment-window-metric_test.sh
	@bash tests/scripts/wait-for-instance-refresh_test.sh
	@bash tests/scripts/deploy-relay_test.sh
	@bash tests/scripts/emit-deployment-window-metric_test.sh
	@shellcheck .github/scripts/verify-asg-instances-healthy.sh .github/scripts/verify-authority-cell-alias-convergence.sh tests/scripts/verify-asg-instances-healthy_test.sh tests/scripts/verify-authority-cell-alias-convergence_test.sh
	@bash tests/scripts/verify-asg-instances-healthy_test.sh
	@bash tests/scripts/verify-authority-cell-alias-convergence_test.sh
	@python3 tests/scripts/test_authority_consumer_cutover_workflow.py
	@shellcheck .github/scripts/resolve-active-image-tag.sh tests/scripts/resolve-active-image-tag_test.sh
	@bash tests/scripts/resolve-active-image-tag_test.sh
	@shellcheck .github/scripts/plan-blue-green-dispatch.sh tests/scripts/plan-blue-green-dispatch_test.sh
	@bash tests/scripts/plan-blue-green-dispatch_test.sh
	@shellcheck scripts/check-app-image-line-rendered.sh tests/scripts/check-app-image-line-rendered_test.sh
	@bash tests/scripts/check-app-image-line-rendered_test.sh
	@shellcheck scripts/check-packer-failure-surfaced.sh tests/lints/packer-failure-surfaced/run-fixtures.sh
	@bash tests/lints/packer-failure-surfaced/run-fixtures.sh
	@shellcheck scripts/check-control-leg-surfaced.sh tests/scripts/check-control-leg-surfaced_test.sh
	@bash tests/scripts/check-control-leg-surfaced_test.sh
	@python3 tests/scripts/test_control_sandbox_runtime_gates.py
	@bash tests/scripts/ami-id-from-manifest_test.sh
	@shellcheck .github/scripts/classify-terraform-plan-pr-changes.sh tests/scripts/classify-terraform-plan-pr-changes_test.sh
	@bash tests/scripts/classify-terraform-plan-pr-changes_test.sh
	@python3 tests/scripts/test_no_invalid_dynamodb_transaction_actions.py
	@python3 tests/scripts/test_qurl_canary_verifier_iam.py
	@python3 -m unittest -v \
		tests.scripts.test_build_sandbox_fixed_canary_plan \
		tests.scripts.test_run_sandbox_fixed_canary_customer_journey \
		tests.scripts.test_sandbox_fixed_canary_authority \
		tests.scripts.test_sandbox_fixed_canary_custody \
		tests.scripts.test_sandbox_fixed_canary_lifecycle_runner \
		tests.scripts.test_sandbox_fixed_canary_runtime_contract \
		tests.scripts.test_sandbox_qurl_customer_workflow \
		tests.scripts.test_verify_sandbox_qurl_customer_artifacts \
		tests.scripts.test_verify_sandbox_qurl_service_provenance
	@python3 tests/scripts/test_qurl_go_otp_mailbox_gate.py
	@python3 tests/scripts/test_prod_hub_dns.py
	@python3 tests/scripts/test_sandbox_cell1_qurl_service_security_contract.py
	@shellcheck scripts/capture-control-update-state.sh scripts/check-control-aws-identity.sh scripts/check-control-global-routing.sh scripts/check-control-vpc-cidr-overlap.sh scripts/check-sandbox-cell1-vpc-relocation-preflight.sh scripts/check-live-main-ref.sh scripts/check-no-checkout-credentials.sh scripts/ensure-control-otp-pepper.sh scripts/verify-control-otp-pepper.sh scripts/verify-control-sandbox-first-apply.sh scripts/verify-control-sandbox-live-boundary.sh tests/fixtures/control-vpc-cidr-overlap/aws tests/fixtures/sandbox-cell1-vpc-relocation/aws tests/scripts/check-control-global-routing_test.sh tests/scripts/check-sandbox-cell1-vpc-relocation-preflight_test.sh
	@python3 tests/scripts/test_check_control_sandbox_first_apply.py
	@python3 tests/scripts/test_check_control_update.py
	@python3 -m py_compile .github/scripts/check-sandbox-cell1-cidr-relocation-plan.py
	@python3 tests/scripts/test_check_sandbox_cell1_cidr_relocation_plan.py
	@python3 tests/scripts/test_generate_connector_authority_runtime_contract.py
	@python3 tests/scripts/test_check_hub_publication_environment.py
	@python3 tests/scripts/test_publish_hub_image.py
	@bash tests/scripts/check-control-global-routing_test.sh
	@bash tests/scripts/check-sandbox-cell1-vpc-relocation-preflight_test.sh
	@python3 tests/scripts/test_summarize_terraform_plan.py
	@python3 tests/scripts/test_relay_trusted_key_validation_lockstep.py
	@python3 -m py_compile .github/scripts/check-relay-dmz-plan.py
	@command -v terraform >/dev/null 2>&1 || \
		echo "$(COLOUR_YELLOW)[OpenNHP] terraform not found: relay DMZ Terraform-backed tests skip locally; set REQUIRE_TERRAFORM=1 for CI parity.$(END_COLOUR)"
	@python3 tests/scripts/test_check_relay_dmz_plan.py
	@python3 -m py_compile scripts/check-relay-dmz-live.py
	@python3 tests/scripts/test_check_relay_dmz_live.py
	@python3 tests/scripts/test_verify_relay_dmz_flow_evidence.py
	@terraform -chdir=terraform/modules/relay-network init -backend=false >/dev/null
	@terraform -chdir=terraform/modules/relay-network test
	@python3 tests/scripts/test_promote_to_prod_gating.py
	@python3 tests/scripts/test_ac_readiness_dependency.py
	@python3 tests/scripts/test_status_page_notification_iam_readiness.py
	@shellcheck .github/scripts/resolve-app-image-required.sh .github/scripts/resolve-live-app-image-required.sh .github/scripts/verify-live-app-images-ready.sh tests/scripts/resolve-app-image-required_test.sh tests/scripts/resolve-live-app-image-required_test.sh tests/scripts/verify-live-app-images-ready_test.sh
	@shellcheck .github/scripts/ssm-live-env-lock.sh \
		.github/scripts/emit-sandbox-lock-failure-metric.sh \
		.github/scripts/classify-blue-green-lock-release.sh \
		scripts/ssm-read-optional.sh
	@bash tests/scripts/resolve-app-image-required_test.sh
	@bash tests/scripts/resolve-live-app-image-required_test.sh
	@bash tests/scripts/verify-live-app-images-ready_test.sh
	@python3 tests/scripts/test_ssm_live_env_lock.py
	@python3 tests/scripts/test_blue_green_lock_release.py
	@bash tests/scripts/check-sandbox-qurl-roll_test.sh
	@command -v node >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] node not found. Install Node.js 18+ to run the qURL relay bootstrap smoke self-test$(END_COLOUR)"; \
		exit 1; \
	}
	@node -e 'const major = Number(process.versions.node.split(".")[0]); if (major < 18) { console.error("Node.js 18+ is required for scripts/qurl-relay-bootstrap-smoke.mjs; found " + process.version); process.exit(1); }'
	@node --check scripts/qurl-relay-bootstrap-smoke.mjs
	@node scripts/qurl-relay-bootstrap-smoke.mjs --self-test
	@node --test terraform/modules/compute/lambda/keygen/index.test.js
	@shellcheck .github/scripts/deploy-ecs-service.sh tests/scripts/deploy-ecs-service_test.sh
	@bash tests/scripts/deploy-ecs-service_test.sh
	@bash tests/scripts/dependabot-go-tidy_test.sh
	@bash tests/lints/paths-filter-coverage/run-fixtures.sh
	@python3 scripts/check-paths-filter-coverage.py
	@shellcheck tests/lints/golangci-config-schema/run-fixtures.sh
	@bash tests/lints/golangci-config-schema/run-fixtures.sh
	@python3 scripts/check-golangci-config-schema.py
	@bash tests/lints/dispatch-ref-error/run-fixtures.sh
	@shellcheck tests/lints/verify-image-attestation/run-fixtures.sh
	@bash tests/lints/verify-image-attestation/run-fixtures.sh
	@shellcheck .github/scripts/scan-attestation-soak.sh tests/lints/attestation-verify-watchdog/run-fixtures.sh
	@bash tests/lints/attestation-verify-watchdog/run-fixtures.sh
	@shellcheck scripts/trigger-prod-deploy.sh tests/lints/ssm-read-failure/run-fixtures.sh
	@bash tests/lints/ssm-read-failure/run-fixtures.sh
	@shellcheck .github/scripts/verify-knock-ready.sh \
		.github/scripts/classify-nhp-server-restart-evidence.sh \
		tests/lints/blue-green-restart-classification/run-fixtures.sh
	@bash tests/lints/blue-green-restart-classification/run-fixtures.sh
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
	@python3 -c 'import hcl2, pytest' >/dev/null 2>&1 || { \
		echo "$(COLOUR_RED)[OpenNHP] python-hcl2 or pytest missing. Install: python3 -m pip install -r .github/scripts/terraform-prod-drift-requirements.txt$(END_COLOUR)"; \
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
	@python3 -m pytest -q tests/scripts/test_auth0_not_terraform_managed.py
	@python3 .github/scripts/check-connector-control-table-schemas.py
	@python3 tests/scripts/test_check_connector_control_table_schemas.py
	@bash tests/scripts/check-connector-authority-foundation_test.sh
	@bash tests/scripts/check-control-global-routing_test.sh
	@bash tests/scripts/check-control-vpc-cidr-overlap_test.sh
	@python3 tests/scripts/test_check_control_sandbox_first_apply.py
	@python3 -m py_compile .github/scripts/check-sandbox-cell1-cidr-relocation-plan.py
	@python3 tests/scripts/test_check_sandbox_cell1_cidr_relocation_plan.py
	@shellcheck scripts/check-sandbox-cell1-vpc-relocation-preflight.sh tests/fixtures/sandbox-cell1-vpc-relocation/aws tests/scripts/check-sandbox-cell1-vpc-relocation-preflight_test.sh
	@bash tests/scripts/check-sandbox-cell1-vpc-relocation-preflight_test.sh
	@python3 tests/scripts/test_check_terraform_plan_pr_policy_readonly.py
	@python3 tests/scripts/test_compute_lifecycle_contract.py
	@python3 tests/scripts/test_ac_tcp_target_group_contract.py
	@python3 tests/scripts/test_security_group_rule_description_charset.py
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
	# endpoints/server/... is not all hermetic, so the broad suite runs behind a
	# narrow -run allowlist of env-free tests. TestConformanceVectors (the qURL v2
	# wire-format conformance vectors, server/internal/qurlv2) is one of them.
	cd endpoints && KBS_SKIP_INIT=1 go test -v ./server/... -run "Test.*ACPeers|TestEmptyVsNil|TestEtcd|TestMerged|TestParse|TestACRegistry|TestConformanceVectors"
	# Connector Hub process/worker tests are hermetic and security-sensitive.
	# Run the package by path so the broad name allowlist above cannot silently
	# skip lifecycle, cancellation, admission, replay, or UDP wire tests.
	cd endpoints && KBS_SKIP_INIT=1 go test -race ./server/hub/... ./server/internal/connectorhub/...
	# qURL static-plugin package runs by PATH, not via a -run name token above:
	# it is hermetic under KBS_SKIP_INIT=1 (no etcd/network/key-init), so the whole
	# package runs here — the WS1 security gate (TestWS1_NoQv2PathCallsInternalV1:
	# no qURL v2 knock path may call a qURL v1 internal endpoint) and every sibling
	# qURL v2 test — robust to renames in a way a name match is not (the "gate that
	# does not gate" regression #2826 guards against). build-and-push.yml also runs
	# this package under -race on code PRs; this line covers the plain-runner
	# `make test` (ubuntu-build.yml) and local runs, where the broad allowlist above
	# would otherwise skip the package. -race mirrors the deleted
	# qurl-v2-qurl-plugin-tests.yml this re-homes (knock driven on concurrent goroutines).
	cd endpoints && KBS_SKIP_INIT=1 go test -race ./server/staticplugins/qurl/...
	# qURL expiry's live e2e harness mirrors qurl-service internals; keep its
	# manifest-backed contract guard in the normal unit lane without touching AWS.
	# This intentionally enters tests/e2e's separate module so module drift cannot
	# hide the always-on fence behind the tagged live-e2e lane.
	cd tests/e2e && go test ./qurl-expiry -count=1
	# The eBPF shared-map parity guards are pure .c-source parsers — no kernel,
	# compiled object, or CAP_BPF needed — so they run here in the plain lane too,
	# not only via the privileged test-ebpf runner. This keeps the "never again"
	# map-type divergence guard (the #2163/#3019 class: an spp declared HASH in one
	# object and LRU_HASH in the other) effective even when the eBPF datapath lane
	# is skipped/red for an unrelated reason. Kernel-requiring tests in the package
	# are excluded by -run, so no CAP_BPF is needed here (#3019 review).
	cd nhp && go test -count=1 ./utils/ebpf/ -run 'TestXdpSource_AdmissionMapsAndConnTrackAreHash|TestTcEgressSource_SppIsHash|TestSharedPinnedMaps_XdpTcParity'
	@echo "$(COLOUR_GREEN)[OpenNHP] Unit Tests Done!$(END_COLOUR)"

# test-ebpf compiles the real XDP object and runs the eBPF datapath tests
# against a LIVE kernel via BPF_PROG_TEST_RUN. This is the #2779
# surgical-kill datapath proof: it loads the compiled nhp_ebpf_xdp.o,
# drives synthetic packets through it, and asserts the verdict flips
# PASS -> DROP after a conntrack entry is surgically flushed (sibling
# survives). REQUIRES a Linux host with CAP_BPF (or CAP_SYS_ADMIN) and a
# kernel that supports XDP program load. NHP_REQUIRE_BPF_TESTS=1 turns any
# missing capability / kernel support / missing object into a hard
# failure instead of a silent skip — set it in CI. The clang findstring
# guard above ensures `clang` is present because `ebpf` is in the goals.
.PHONY: test-ebpf
test-ebpf: $(EBPF_OBJ_XDP)
	@echo "[OpenNHP] Running eBPF datapath tests (BPF_PROG_TEST_RUN)..."
	@echo "$(COLOUR_BLUE)[eBPF] XDP object: $(EBPF_OBJ_XDP)$(END_COLOUR)"
	cd nhp && NHP_EBPF_XDP_OBJECT="$(abspath $(EBPF_OBJ_XDP))" \
		NHP_REQUIRE_BPF_TESTS=$${NHP_REQUIRE_BPF_TESTS:-1} \
		go test -v -count=1 ./utils/ebpf/...
	@echo "$(COLOUR_GREEN)[OpenNHP] eBPF datapath tests Done!$(END_COLOUR)"

test-lambdas: ## Run Lambda unit tests (Python)
	@echo "[OpenNHP] Running Lambda Unit Tests..."
	python3 -m pytest terraform/modules/billing/lambda/test_*.py terraform/modules/developer-portal/lambda/test_*.py -v
	@echo "$(COLOUR_GREEN)[OpenNHP] Lambda Unit Tests Done!$(END_COLOUR)"

test-local: ## Run local e2e tests (requires: docker compose -f tests/local/docker-compose.test.yaml up -d etcd)
	@echo "[OpenNHP] Running Local E2E Tests..."
	cd tests/local && go test -v -tags=local ./...
	@echo "$(COLOUR_GREEN)[OpenNHP] Local E2E Tests Done!$(END_COLOUR)"

# Smoke tests run via scripts/run-smoke.sh — the single entrypoint shared by
# local runs, PR CI, and post-deploy CI (see tests/smoke/doc.go for the env
# matrix and capability map; tests/smoke/CLAUDE.md for the suite rules). The
# tier -> RUN_FILTER mapping and env-derived flags live in that script, so
# these targets only supply credentials and the target name.

# test-smoke-local needs no AWS or Auth0: scripts/run-smoke.sh brings up a
# self-contained stack (nhp-server + nhp-ac + dynamodb-local) via docker
# compose and runs the wire-contract `local` tier against the freshly-built
# binaries.
# Requires Docker + the AWS CLI (for dynamodb-local table creation).
test-smoke-local: ## Run smoke tests against a self-contained local stack (Docker)
	@echo "[OpenNHP] Running smoke tests against the local stack..."
	TARGET=local ./scripts/run-smoke.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] Local smoke tests done!$(END_COLOUR)"

# smoke-build is the credential-free PR-time gate: it compiles and vets the
# smoke suite under -tags=smoke (the module is otherwise never built at PR
# time — codeql builds nhp/internalauth/endpoints only) and runs the tier
# filter coverage fence. Catches a smoke test that doesn't compile before it
# reaches post-deploy CI on main.
smoke-build: ## Compile + vet the smoke suite and check tier filter coverage (no creds)
	@echo "[OpenNHP] Building + vetting smoke suite (-tags=smoke)..."
	cd tests/smoke && go build -tags=smoke ./... && go vet -tags=smoke ./...
	@echo "[OpenNHP] Running the credential-free smoke tests (restart-evidence classification)..."
	@# `go test -run` exits 0 when its pattern matches nothing, so the grep is
	@# what stops a renamed test from turning this into a green no-op.
	cd tests/smoke && NHP_ENVIRONMENT=local go test -tags=smoke -count=1 -v \
		-run 'TestRestartEvidence|TestParseSystemdExitLines|TestLastMeaningfulDaemonError|TestParseUnitState|TestParallelSubtestsDontInheritCanceledCtx' ./... \
		| tee /tmp/nhp-smoke-restart-evidence.log
	@if grep -q 'no tests to run' /tmp/nhp-smoke-restart-evidence.log; then \
		echo "$(COLOUR_RED)[OpenNHP] The -run pattern matched no tests — nothing was asserted.$(END_COLOUR)"; \
		rm -f /tmp/nhp-smoke-restart-evidence.log; exit 1; \
	fi
	@rm -f /tmp/nhp-smoke-restart-evidence.log
	@bash scripts/check-smoke-tier-filter-coverage.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] Smoke build/vet done!$(END_COLOUR)"

# test-smoke-sandbox uses AWS_PROFILE=layerv. Override the tier with e.g.
# `TIER=tier1 make test-smoke-sandbox`. No Auth0/Secrets-Manager fetch — the
# qURL-minting smoke tests were moved out of nhp (qURL smoke belongs in
# qurl-service; see tests/smoke/CLAUDE.md).
test-smoke-sandbox: ## Run smoke tests against sandbox (uses AWS_PROFILE=layerv)
	@echo "[OpenNHP] Running smoke tests against sandbox..."
	AWS_PROFILE=layerv \
	AWS_REGION=us-east-2 \
	TARGET=sandbox \
	TIER=$${TIER:-all} \
	NHP_SMOKE_ALLOW_SSM_PROBES=true \
	./scripts/run-smoke.sh
	@echo "$(COLOUR_GREEN)[OpenNHP] Sandbox smoke tests done!$(END_COLOUR)"

# test-smoke-prod uses AWS_PROFILE=layerv-prod. SSM probes are OFF by
# default during the 30-day burn-in; pass NHP_SMOKE_ALLOW_SSM_PROBES=true
# on the command line to override.
test-smoke-prod: ## Run smoke tests against prod (uses AWS_PROFILE=layerv-prod)
	@echo "[OpenNHP] Running smoke tests against PROD..."
	AWS_PROFILE=layerv-prod \
	AWS_REGION=us-east-2 \
	TARGET=prod \
	TIER=$${TIER:-all} \
	NHP_SMOKE_ALLOW_SSM_PROBES=$${NHP_SMOKE_ALLOW_SSM_PROBES:-false} \
	./scripts/run-smoke.sh
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
	@cd release && mkdir -p archive && tar -czvf ./archive/$(PACKAGE_FILE) nhp-agent nhp-ac nhp-db nhp-server nhp-relay nhp-hub
	@echo "$(COLOUR_GREEN)[OpenNHP] Package ${PACKAGE_FILE} archived!$(END_COLOUR)"

.PHONY: all generate-version-and-build init agentd acd serverd relayd hubd db licenseadmin linuxagentsdk androidagentsdk macosagentsdk iosagentsdk devicesdk plugins lint test test-lambdas test-local test-smoke-local smoke-build test-smoke-sandbox test-smoke-prod test-all fuzz fuzz-quick archive ebpf clean_ebpf
