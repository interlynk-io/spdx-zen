# Copyright 2024 Interlynk.io
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.DEFAULT_GOAL := help

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Version information
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_HASH ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null)
ifdef SOURCE_DATE_EPOCH
  BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
  BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif
GIT_TREESTATE = clean
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = dirty
endif

# Build variables
PKG ?= sigs.k8s.io/release-utils/version
LDFLAGS = -buildid= -X $(PKG).gitVersion=$(GIT_VERSION) \
          -X $(PKG).gitCommit=$(GIT_HASH) \
          -X $(PKG).gitTreeState=$(GIT_TREESTATE) \
          -X $(PKG).buildDate=$(BUILD_DATE)

BUILD_DIR = ./bin
BINARY_NAME = spdx-gen
TARGETOS ?= $(shell go env GOOS)
TARGETARCH ?= $(shell go env GOARCH)

##@ General

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

.PHONY: generate
generate: ## Run go generate
	@echo "Running go generate..."
	@go generate ./...

.PHONY: fmt
fmt: ## Run go fmt
	@echo "Formatting code..."
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

.PHONY: lint
lint: ## Run golangci-lint (requires golangci-lint installed)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/"; \
		echo "Running go vet instead..."; \
		go vet ./...; \
	fi

##@ Testing

.PHONY: test
test: ## Run all tests
	@echo "Running tests..."
	@go test -cover -race ./...

.PHONY: test-verbose
test-verbose: ## Run all tests with verbose output
	@echo "Running tests (verbose)..."
	@go test -v -cover -race ./...

.PHONY: coverage
coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	@go test -cover -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

##@ Building

.PHONY: build
build: ## Build binary for current platform
	@echo "Building $(BINARY_NAME) for $(TARGETOS)/$(TARGETARCH)..."
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/spdx-gen

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/spdx-gen
	@GOOS=linux GOARCH=arm64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/spdx-gen
	@GOOS=darwin GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/spdx-gen
	@GOOS=darwin GOARCH=arm64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/spdx-gen
	@GOOS=windows GOARCH=amd64 go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/spdx-gen
	@echo "Build complete. Binaries in $(BUILD_DIR)/"

.PHONY: examples
examples: ## Build example applications
	@echo "Building examples..."
	@mkdir -p $(BUILD_DIR)
	@cd examples/spdx-lister && go build -o ../../$(BUILD_DIR)/spdx-lister .

.PHONY: install
install: build ## Install binary to GOBIN
	@echo "Installing $(BINARY_NAME) to $(GOBIN)..."
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(GOBIN)/$(BINARY_NAME)
	@echo "Installed to $(GOBIN)/$(BINARY_NAME)"

##@ Release

.PHONY: snapshot
snapshot: ## Create a snapshot release (without publishing)
	@echo "Creating snapshot release..."
	@goreleaser release --clean --snapshot --skip=publish

.PHONY: release
release: ## Create a release (requires proper git tag)
	@echo "Creating release..."
	@goreleaser release --clean

##@ Maintenance

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) dist/ coverage.out coverage.html

.PHONY: clean-all
clean-all: clean ## Clean all artifacts including caches
	@echo "Cleaning all artifacts..."
	@go clean -cache -testcache -modcache

.PHONY: update-deps
update-deps: ## Update all dependencies
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

.PHONY: tidy
tidy: ## Run go mod tidy
	@echo "Tidying go.mod..."
	@go mod tidy

##@ CI/CD

.PHONY: ci
ci: deps generate vet test ## Run CI pipeline locally
	@echo "CI pipeline complete"

.PHONY: pre-commit
pre-commit: fmt vet lint test ## Run pre-commit checks
	@echo "Pre-commit checks passed"
