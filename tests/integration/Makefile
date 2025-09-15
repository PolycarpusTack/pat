# Fortress Integration Test Makefile
# 
# This Makefile provides comprehensive integration test execution targets
# for the Pat Fortress email testing platform

.PHONY: help test-all test-unit test-integration test-performance test-coverage \
        test-docker test-protocol test-services test-external test-pipeline \
        test-orchestration clean-coverage clean-artifacts setup-env \
        ci-test ci-coverage ci-report

# Default target
help: ## Display this help message
	@echo "🏰 FORTRESS INTEGRATION TEST SUITE"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# Environment setup
FORTRESS_ENV ?= test
GO_VERSION ?= 1.21
COVERAGE_THRESHOLD ?= 95
DOCKER_COMPOSE_FILE ?= ../../../docker-compose.test.yml
PROJECT_ROOT ?= ../../..

# Test execution settings
TEST_TIMEOUT ?= 45m
TEST_PARALLEL ?= 4
TEST_RACE ?= true
TEST_COVERAGE ?= true
TEST_VERBOSE ?= true

# Coverage output
COVERAGE_DIR = coverage
COVERAGE_HTML = $(COVERAGE_DIR)/coverage.html
COVERAGE_XML = $(COVERAGE_DIR)/coverage.xml
COVERAGE_OUT = $(COVERAGE_DIR)/coverage.out

# Test result directories
RESULTS_DIR = results
REPORTS_DIR = reports

# Environment variables for tests
export FORTRESS_ENV
export FORTRESS_LOG_LEVEL = debug
export FORTRESS_DEBUG = true
export CGO_ENABLED = 1
export GO111MODULE = on

# Test database configuration
export FORTRESS_TEST_DB_HOST ?= localhost
export FORTRESS_TEST_DB_PORT ?= 5433
export FORTRESS_TEST_DB_NAME ?= pat_fortress_test
export FORTRESS_TEST_DB_USER ?= pat_test
export FORTRESS_TEST_DB_PASSWORD ?= test_password

# Test Redis configuration
export FORTRESS_TEST_REDIS_ADDRESS ?= localhost:6380
export FORTRESS_TEST_REDIS_PASSWORD ?= 
export FORTRESS_TEST_REDIS_DB ?= 1

# Docker test configuration
export SKIP_DOCKER_TESTS ?= false

# Create necessary directories
$(COVERAGE_DIR):
	@mkdir -p $(COVERAGE_DIR)

$(RESULTS_DIR):
	@mkdir -p $(RESULTS_DIR)

$(REPORTS_DIR):
	@mkdir -p $(REPORTS_DIR)

# Setup test environment
setup-env: $(COVERAGE_DIR) $(RESULTS_DIR) $(REPORTS_DIR) ## Setup test environment and directories
	@echo "🔧 Setting up Fortress test environment..."
	@go mod download
	@go mod tidy
	@echo "✅ Test environment ready"

# Clean targets
clean-coverage: ## Remove coverage files
	@echo "🧹 Cleaning coverage files..."
	@rm -rf $(COVERAGE_DIR)
	@rm -f coverage_*.out
	@echo "✅ Coverage files cleaned"

clean-artifacts: ## Remove all test artifacts
	@echo "🧹 Cleaning test artifacts..."
	@rm -rf $(COVERAGE_DIR) $(RESULTS_DIR) $(REPORTS_DIR)
	@rm -f coverage_*.out *.test
	@echo "✅ Test artifacts cleaned"

# Unit tests
test-unit: setup-env ## Run all unit tests with coverage
	@echo "🔬 Running Fortress unit tests..."
	@go test -v -race -timeout=10m -coverprofile=$(COVERAGE_DIR)/unit_coverage.out \
		-covermode=atomic ./unit/...
	@echo "✅ Unit tests completed"

# Integration test suites
test-email-pipeline: setup-env ## Run email processing pipeline integration tests
	@echo "📧 Running email processing pipeline tests..."
	@go test -v -race -timeout=8m -tags=integration \
		-coverprofile=$(COVERAGE_DIR)/pipeline_coverage.out \
		./email_processing/...
	@echo "✅ Email pipeline tests completed"

test-services: setup-env ## Run service integration tests
	@echo "🔗 Running service integration tests..."
	@go test -v -race -timeout=10m -tags=integration \
		-coverprofile=$(COVERAGE_DIR)/services_coverage.out \
		./service_integration/...
	@echo "✅ Service integration tests completed"

test-external: setup-env ## Run external system integration tests
	@echo "🔌 Running external system integration tests..."
	@go test -v -race -timeout=10m -tags=integration \
		-coverprofile=$(COVERAGE_DIR)/external_coverage.out \
		./external_systems/...
	@echo "✅ External system tests completed"

test-protocol: setup-env ## Run protocol compliance tests
	@echo "📡 Running protocol compliance tests..."
	@go test -v -race -timeout=8m -tags=integration \
		-coverprofile=$(COVERAGE_DIR)/protocol_coverage.out \
		./protocol_compliance/...
	@echo "✅ Protocol compliance tests completed"

test-docker: setup-env ## Run Docker deployment integration tests
	@echo "🐳 Running Docker integration tests..."
	@go test -v -race -timeout=15m -tags=docker \
		-coverprofile=$(COVERAGE_DIR)/docker_coverage.out \
		./deployment/...
	@echo "✅ Docker integration tests completed"

test-orchestration: setup-env ## Run test orchestration suite
	@echo "🎭 Running test orchestration..."
	@go test -v -race -timeout=$(TEST_TIMEOUT) -tags=orchestration \
		./orchestration/...
	@echo "✅ Test orchestration completed"

# Performance and benchmark tests
test-performance: setup-env ## Run performance benchmarks
	@echo "🚀 Running performance benchmarks..."
	@go test -v -bench=. -benchmem -timeout=15m \
		-benchtime=10s ./benchmarks/...
	@echo "✅ Performance benchmarks completed"

# Integration test suites (sequential)
test-integration-sequential: setup-env ## Run integration tests sequentially
	@echo "🏰 Running Fortress integration tests (Sequential)..."
	$(MAKE) test-external
	$(MAKE) test-services
	$(MAKE) test-email-pipeline
	$(MAKE) test-protocol
	@echo "✅ Sequential integration tests completed"

# Integration test suites (parallel where possible)
test-integration-parallel: setup-env ## Run integration tests in parallel where safe
	@echo "🏰 Running Fortress integration tests (Parallel)..."
	@echo "⚡ Starting parallel test execution..."
	@($(MAKE) test-external & \
	  $(MAKE) test-services & \
	  $(MAKE) test-email-pipeline & \
	  $(MAKE) test-protocol & \
	  wait)
	@echo "✅ Parallel integration tests completed"

# Complete integration test suite
test-integration: setup-env ## Run complete integration test suite
	@echo "🏰 FORTRESS COMPREHENSIVE INTEGRATION TESTING"
	@echo "============================================="
	@echo "Starting comprehensive integration test execution..."
	@echo ""
	$(MAKE) test-integration-sequential
	@if [ "$(SKIP_DOCKER_TESTS)" != "true" ]; then \
		$(MAKE) test-docker; \
	else \
		echo "⚠️  Docker tests skipped (SKIP_DOCKER_TESTS=true)"; \
	fi
	@echo ""
	@echo "🎯 Running test orchestration..."
	$(MAKE) test-orchestration
	@echo ""
	@echo "✅ FORTRESS INTEGRATION TESTING COMPLETED"

# Complete test suite (unit + integration + performance)
test-all: setup-env ## Run all tests (unit + integration + performance)
	@echo "🏰 FORTRESS COMPREHENSIVE TEST SUITE"
	@echo "===================================="
	@echo ""
	$(MAKE) test-unit
	@echo ""
	$(MAKE) test-integration
	@echo ""
	$(MAKE) test-performance
	@echo ""
	@echo "✅ ALL FORTRESS TESTS COMPLETED"

# Coverage analysis
test-coverage: setup-env ## Generate comprehensive coverage report
	@echo "📊 Generating comprehensive coverage report..."
	@echo "Combining coverage files..."
	@echo "mode: atomic" > $(COVERAGE_OUT)
	@find . -name 'coverage_*.out' -exec grep -h -v "^mode:" {} \; >> $(COVERAGE_OUT) 2>/dev/null || true
	@echo "Generating HTML coverage report..."
	@go tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@echo "Generating coverage summary..."
	@go tool cover -func=$(COVERAGE_OUT) | tee $(COVERAGE_DIR)/coverage_summary.txt
	@echo ""
	@echo "Coverage threshold check ($(COVERAGE_THRESHOLD)%)..."
	@COVERAGE=$$(go tool cover -func=$(COVERAGE_OUT) | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE >= $(COVERAGE_THRESHOLD)" | bc -l)" = "1" ]; then \
		echo "✅ Coverage $$COVERAGE% meets threshold $(COVERAGE_THRESHOLD)%"; \
	else \
		echo "❌ Coverage $$COVERAGE% below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi
	@echo ""
	@echo "📊 Coverage report: $(COVERAGE_HTML)"
	@echo "📄 Coverage summary: $(COVERAGE_DIR)/coverage_summary.txt"

# CI/CD integration targets
ci-deps: ## Install CI dependencies
	@echo "🔧 Installing CI dependencies..."
	@go version
	@go mod download
	@go mod verify
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

ci-lint: ## Run linting for CI
	@echo "🔍 Running linting checks..."
	@golangci-lint run ./...

ci-test: ci-deps ## Run tests for CI environment
	@echo "🤖 Running CI test suite..."
	@echo "Environment: $(FORTRESS_ENV)"
	@echo "Go version: $$(go version)"
	@echo ""
	$(MAKE) test-unit
	@echo ""
	@if [ "$(CI_SKIP_INTEGRATION)" != "true" ]; then \
		$(MAKE) test-integration-sequential; \
	else \
		echo "⚠️  Integration tests skipped in CI"; \
	fi

ci-coverage: ci-test ## Generate coverage for CI
	@echo "📊 Generating CI coverage report..."
	$(MAKE) test-coverage
	@echo "Converting coverage to XML format..."
	@go install github.com/axw/gocov/gocov@latest
	@go install github.com/AlekSi/gocov-xml@latest
	@gocov convert $(COVERAGE_OUT) | gocov-xml > $(COVERAGE_XML)
	@echo "✅ CI coverage report generated"

ci-report: $(REPORTS_DIR) ## Generate CI test reports
	@echo "📋 Generating CI test reports..."
	@cp $(COVERAGE_HTML) $(REPORTS_DIR)/
	@cp $(COVERAGE_XML) $(REPORTS_DIR)/
	@cp $(COVERAGE_DIR)/coverage_summary.txt $(REPORTS_DIR)/
	@if [ -f "FORTRESS_INTEGRATION_TEST_REPORT.md" ]; then \
		cp FORTRESS_INTEGRATION_TEST_REPORT.md $(REPORTS_DIR)/; \
	fi
	@echo "✅ CI reports ready in $(REPORTS_DIR)/"

# Quick test targets for development
test-quick: ## Run quick tests (unit tests only)
	@echo "⚡ Running quick test suite..."
	@go test -short -race ./unit/...
	@echo "✅ Quick tests completed"

test-watch: ## Run tests in watch mode (requires entr)
	@echo "👀 Starting test watch mode..."
	@find . -name '*.go' | entr -c make test-quick

# Development helpers
test-debug: ## Run tests with debug output
	@echo "🐛 Running tests with debug output..."
	@FORTRESS_LOG_LEVEL=debug FORTRESS_DEBUG=true \
		go test -v -race ./unit/... ./email_processing/...

test-profile: setup-env ## Run tests with CPU profiling
	@echo "📈 Running tests with profiling..."
	@go test -cpuprofile=$(RESULTS_DIR)/cpu.prof -memprofile=$(RESULTS_DIR)/mem.prof \
		-bench=. ./benchmarks/...
	@echo "Profile files generated in $(RESULTS_DIR)/"

# Test environment management
start-test-services: ## Start test services (Docker)
	@echo "🐳 Starting test services..."
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 10
	@echo "✅ Test services started"

stop-test-services: ## Stop test services (Docker)
	@echo "🛑 Stopping test services..."
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v
	@echo "✅ Test services stopped"

restart-test-services: ## Restart test services
	$(MAKE) stop-test-services
	$(MAKE) start-test-services

# Validation and quality checks
validate-tests: ## Validate test suite completeness
	@echo "🔍 Validating test suite..."
	@echo "Checking for test coverage..."
	@find ./unit ./email_processing ./service_integration ./external_systems ./protocol_compliance \
		-name '*_test.go' | wc -l | awk '{printf "Found %d test files\n", $$1}'
	@echo "Checking for benchmark tests..."
	@find ./benchmarks -name '*_test.go' 2>/dev/null | wc -l | awk '{printf "Found %d benchmark files\n", $$1}'
	@echo "✅ Test suite validation completed"

# Documentation generation
docs-coverage: test-coverage ## Generate coverage documentation
	@echo "📚 Generating coverage documentation..."
	@echo "# Fortress Test Coverage Report" > $(REPORTS_DIR)/COVERAGE.md
	@echo "" >> $(REPORTS_DIR)/COVERAGE.md
	@echo "Generated on: $$(date)" >> $(REPORTS_DIR)/COVERAGE.md
	@echo "" >> $(REPORTS_DIR)/COVERAGE.md
	@echo "## Overall Coverage" >> $(REPORTS_DIR)/COVERAGE.md
	@echo "" >> $(REPORTS_DIR)/COVERAGE.md
	@echo '```' >> $(REPORTS_DIR)/COVERAGE.md
	@cat $(COVERAGE_DIR)/coverage_summary.txt >> $(REPORTS_DIR)/COVERAGE.md
	@echo '```' >> $(REPORTS_DIR)/COVERAGE.md
	@echo "✅ Coverage documentation generated"

# Help and information
info: ## Display environment information
	@echo "🏰 FORTRESS TEST ENVIRONMENT INFO"
	@echo "================================"
	@echo "Go Version: $$(go version)"
	@echo "Project Root: $(PROJECT_ROOT)"
	@echo "Fortress Env: $(FORTRESS_ENV)"
	@echo "Test Timeout: $(TEST_TIMEOUT)"
	@echo "Coverage Threshold: $(COVERAGE_THRESHOLD)%"
	@echo "Docker Tests: $(if $(filter true,$(SKIP_DOCKER_TESTS)),Disabled,Enabled)"
	@echo ""
	@echo "Database Config:"
	@echo "  Host: $(FORTRESS_TEST_DB_HOST):$(FORTRESS_TEST_DB_PORT)"
	@echo "  Database: $(FORTRESS_TEST_DB_NAME)"
	@echo "  User: $(FORTRESS_TEST_DB_USER)"
	@echo ""
	@echo "Redis Config:"
	@echo "  Address: $(FORTRESS_TEST_REDIS_ADDRESS)"
	@echo "  Database: $(FORTRESS_TEST_REDIS_DB)"
	@echo ""

# Default target points to help
.DEFAULT_GOAL := help