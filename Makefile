.PHONY: help build build-all run test test-race test-coverage bench clean lint fmt deps update install uninstall release security-check

# Build configuration
BINARY_NAME=shamir
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

# Go configuration
GO=go
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

# Directories
BUILD_DIR=bin
COVERAGE_DIR=coverage
CMD_DIR=cmd/shamir

help: ## Show this help message
	@echo 'Shamir - Secure Cryptocurrency Wallet Backup Tool'
	@echo ''
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the CLI binary
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Built $(BINARY_NAME) for $(GOOS)/$(GOARCH)"

build-all: ## Build binaries for all platforms
	@mkdir -p $(BUILD_DIR)
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	GOOS=freebsd GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64 ./$(CMD_DIR)
	@echo "Built binaries for all platforms in $(BUILD_DIR)/"

run: ## Run the CLI locally
	$(GO) run ./$(CMD_DIR)

test: ## Run all tests with coverage
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -v -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

test-race: ## Run tests with race detector
	$(GO) test -v -race ./...

test-coverage: ## Generate detailed test coverage
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -v -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total:
	@echo "Detailed coverage report: $(COVERAGE_DIR)/coverage.html"

test-integration: ## Run integration tests only
	$(GO) test -v ./test/...

bench: ## Run benchmarks
	$(GO) test -bench=. -benchmem -run=^$$ ./...

bench-compare: ## Run benchmarks and save results for comparison
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test -bench=. -benchmem -run=^$$ ./... | tee $(COVERAGE_DIR)/bench-$(shell date +%Y%m%d-%H%M%S).txt

clean: ## Clean build artifacts and caches
	rm -rf $(BUILD_DIR)/ $(COVERAGE_DIR)/
	$(GO) clean -cache -testcache -modcache
	@echo "Cleaned build artifacts and caches"

lint: ## Run linters
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Installing golangci-lint..."; $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; }
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...
	@command -v goimports >/dev/null 2>&1 || { echo "Installing goimports..."; $(GO) install golang.org/x/tools/cmd/goimports@latest; }
	goimports -w .

deps: ## Download and verify dependencies
	$(GO) mod download
	$(GO) mod verify

update: ## Update dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

install: build ## Install binary to GOBIN
	@if [ -z "$(GOBIN)" ]; then \
		echo "Installing to $(shell go env GOPATH)/bin/$(BINARY_NAME)"; \
		cp $(BUILD_DIR)/$(BINARY_NAME) $(shell go env GOPATH)/bin/; \
	else \
		echo "Installing to $(GOBIN)/$(BINARY_NAME)"; \
		cp $(BUILD_DIR)/$(BINARY_NAME) $(GOBIN)/; \
	fi

uninstall: ## Remove installed binary
	@if [ -z "$(GOBIN)" ]; then \
		rm -f $(shell go env GOPATH)/bin/$(BINARY_NAME); \
		echo "Removed $(shell go env GOPATH)/bin/$(BINARY_NAME)"; \
	else \
		rm -f $(GOBIN)/$(BINARY_NAME); \
		echo "Removed $(GOBIN)/$(BINARY_NAME)"; \
	fi

release: clean build-all test security-check ## Prepare release builds
	@echo "Release build complete. Binaries in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

security-check: ## Run security checks
	@echo "Running security checks..."
	$(GO) vet ./...
	@command -v gosec >/dev/null 2>&1 || { echo "Installing gosec..."; $(GO) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; }
	gosec -quiet ./...
	@echo "Security checks passed"

docker-build: ## Build Docker image
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

docker-run: ## Run Docker container
	docker run --rm -it $(BINARY_NAME):latest

validate: ## Validate the codebase
	@echo "Validating codebase..."
	$(GO) vet ./...
	$(GO) mod verify
	gofmt -l . | grep -E '.*' && { echo "Code not formatted. Run 'make fmt'"; exit 1; } || echo "Code formatting OK"
	@echo "Validation complete"

cli-test: build ## Test CLI commands
	@echo "Testing CLI functionality..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --version
	@echo "test secret" | ./$(BUILD_DIR)/$(BINARY_NAME) split --parts 3 --threshold 2 --stdin --json
	@./$(BUILD_DIR)/$(BINARY_NAME) generate --words 12 --json
	@echo "CLI tests passed"

install-tools: ## Install development tools
	@echo "Installing development tools..."
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "Development tools installed"

check: validate test lint security-check ## Run all checks (validate, test, lint, security)
	@echo "All checks passed ✅"

info: ## Show build information
	@echo "Build Information:"
	@echo "  Binary Name: $(BINARY_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Go Version: $(shell $(GO) version)"
	@echo "  Target: $(GOOS)/$(GOARCH)"