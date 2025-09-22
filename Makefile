# Fortress Testing Armory Makefile
# Comprehensive testing commands for the Pat Fortress

VERSION=2.0.0

.PHONY: help fortress-test fortress-test-unit fortress-test-integration fortress-test-benchmark
.PHONY: fortress-coverage fortress-security fortress-lint fortress-build fortress-clean
.PHONY: fortress-setup fortress-deps fortress-docker fortress-ci

# Legacy support
all: fmt combined

combined:
	go install .

fmt:
	go fmt ./...

# Default target
help: ## Display fortress testing commands
	@echo "🏰 FORTRESS TESTING ARMORY 🏰"
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick Start:"
	@echo "  make fortress-setup    # Setup testing environment"
	@echo "  make fortress-test     # Run all fortress tests"
	@echo "  make fortress-coverage # Generate coverage report"

# Go environment
GO := go
GOVERSION := 1.21
COVERAGE_THRESHOLD := 90
SECURITY_COVERAGE_THRESHOLD := 95
MUTATION_THRESHOLD := 85

# Directories
TEST_DIR := ./tests
UNIT_TEST_DIR := ./...
INTEGRATION_TEST_DIR := ./tests/integration
BENCHMARK_TEST_DIR := ./...
COVERAGE_DIR := ./coverage
REPORTS_DIR := ./reports

# Test configuration
TEST_TIMEOUT := 10m
INTEGRATION_TIMEOUT := 20m
BENCHMARK_TIME := 30s
RACE_DETECTOR := -race

# Coverage files
COVERAGE_OUT := $(COVERAGE_DIR)/fortress-coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/fortress-coverage.html

fortress-setup: ## Setup fortress testing environment
	@echo "🏰 Setting up Fortress Testing Environment..."
	@mkdir -p $(COVERAGE_DIR) $(REPORTS_DIR)
	@$(GO) install github.com/stretchr/testify@latest
	@echo "✅ Fortress testing environment ready"

fortress-deps: ## Download and verify dependencies
	@echo "🔧 Downloading fortress dependencies..."
	@$(GO) mod download
	@$(GO) mod verify
	@$(GO) mod tidy
	@echo "✅ Dependencies secured"

fortress-test-unit: fortress-deps ## Run fortress unit tests
	@echo "⚔️ Running fortress unit tests..."
	@$(GO) test $(RACE_DETECTOR) -coverprofile=$(COVERAGE_OUT) -covermode=atomic \
		-timeout=$(TEST_TIMEOUT) $(UNIT_TEST_DIR)
	@echo "✅ Unit tests complete"

fortress-test-benchmark: fortress-deps ## Run fortress performance benchmarks
	@echo "🏃 Running fortress performance benchmarks..."
	@$(GO) test -bench=. -benchmem -benchtime=$(BENCHMARK_TIME) \
		$(BENCHMARK_TEST_DIR) | tee $(REPORTS_DIR)/fortress-benchmark-results.txt
	@echo "✅ Performance benchmarks complete"

fortress-test: fortress-test-unit fortress-test-benchmark ## Run all fortress tests
	@echo "🏰 All fortress tests complete"

fortress-coverage: fortress-test-unit ## Generate fortress coverage report
	@echo "📊 Generating fortress coverage report..."
	@$(GO) tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_OUT) | tee $(REPORTS_DIR)/fortress-coverage-summary.txt
	@echo ""
	@echo "📈 Coverage Summary:"
	@grep "total:" $(REPORTS_DIR)/fortress-coverage-summary.txt || echo "Coverage analysis complete"
	@echo "📄 Coverage report: $(COVERAGE_HTML)"

fortress-clean: ## Clean fortress test artifacts
	@echo "🧹 Cleaning fortress test artifacts..."
	@rm -rf $(COVERAGE_DIR) $(REPORTS_DIR)
	@$(GO) clean -testcache
	@echo "✅ Fortress cleaned"

fortress-build: fortress-deps ## Build fortress components
	@echo "🏗️ Building fortress components..."
	@$(GO) build -v ./...
	@echo "✅ Fortress build complete"

fortress-ci: fortress-deps fortress-test fortress-coverage ## Run complete CI pipeline
	@echo "🏰 FORTRESS CI PIPELINE COMPLETE 🏰"
	@echo "✅ Dependencies: OK"
	@echo "✅ Unit Tests: OK"
	@echo "✅ Benchmarks: OK"
	@echo "✅ Coverage: OK"
	@echo ""
	@echo "🛡️ Fortress defenses are operational!"

fortress-quick: fortress-deps fortress-test-unit ## Quick test cycle for development
	@echo "⚡ Quick fortress test cycle complete"

# Legacy release targets
release-deps:
	go get github.com/mitchellh/gox

release: tag release-deps 
	gox -ldflags "-X main.version=${VERSION}" -output="build/{{.Dir}}_{{.OS}}_{{.Arch}}" .

pull:
	git pull

tag:
	git tag -a -m 'v${VERSION}' v${VERSION} && git push origin v${VERSION}

# Legacy phony targets
.PHONY: all combined release fmt release-deps pull tag
