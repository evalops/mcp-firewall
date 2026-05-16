SHELL := /usr/bin/env bash

GO ?= go
BUILD_DIR ?= /tmp/evalops-mcp-firewall-build
BAZEL ?= $(shell if command -v bazelisk >/dev/null 2>&1; then command -v bazelisk; elif command -v go >/dev/null 2>&1; then printf '%s/bin/bazelisk' "$$(go env GOPATH)"; else printf bazelisk; fi)
BUILDIFIER ?= $(shell if command -v buildifier >/dev/null 2>&1; then command -v buildifier; elif command -v go >/dev/null 2>&1; then printf '%s/bin/buildifier' "$$(go env GOPATH)"; else printf buildifier; fi)
BAZEL_TARGETS ?= //...
BAZEL_REMOTE_CONFIG ?= remote-gcp-dev
BAZEL_RBE_SMOKE_TARGETS ?= //cmd/mcp-firewall:mcp-firewall //internal/firewall:firewall_test
BAZEL_CI_REMOTE_DOWNLOAD_FLAGS ?= --remote_download_outputs=minimal

.PHONY: bazel-check bazel-format bazel-gazelle bazel-mod-tidy bazel-rbe-smoke bazel-test bazel-test-remote build check diff-check fmt fmt-check test vet

build:
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/mcp-firewall ./cmd/mcp-firewall

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@test -z "$$(gofmt -l ./cmd ./internal)"

diff-check:
	git diff --check

check: fmt-check diff-check build test vet

bazel-mod-tidy:
	$(BAZEL) mod tidy

bazel-gazelle:
	$(BAZEL) run //:gazelle

bazel-format:
	$(BUILDIFIER) -r .

bazel-check:
	$(MAKE) bazel-mod-tidy
	$(MAKE) bazel-gazelle
	$(MAKE) bazel-format
	git diff --exit-code

bazel-test:
	$(BAZEL) test $(BAZEL_TARGETS)

bazel-test-remote:
	$(BAZEL) test --config=$(BAZEL_REMOTE_CONFIG) $(BAZEL_TARGETS)

bazel-rbe-smoke:
	scripts/run-bazel-rbe.sh -- $(BAZEL) test --config=$(BAZEL_REMOTE_CONFIG) $(BAZEL_CI_REMOTE_DOWNLOAD_FLAGS) $(BAZEL_RBE_SMOKE_TARGETS)
