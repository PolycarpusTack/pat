#!/bin/bash

# PAT FORTRESS - PHASE 3 VALIDATION
# Validates completion of Testing & Quality Assurance phase

set -euo pipefail

readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly TESTING_DIR="${PROJECT_ROOT}/test"
readonly MIN_COVERAGE_TARGET=90

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_NC='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${COLOR_BLUE}[INFO]${COLOR_NC}  ${timestamp} - $message" ;;
        "WARN")  echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC}  ${timestamp} - $message" ;;
        "ERROR") echo -e "${COLOR_RED}[ERROR]${COLOR_NC} ${timestamp} - $message" ;;
        "SUCCESS") echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} ${timestamp} - $message" ;;
    esac
}

validate_unit_tests() {
    log "INFO" "Validating unit test implementation..."
    
    cd "$PROJECT_ROOT"
    
    # Check if test utilities exist
    if [ -f "${TESTING_DIR}/testutil/helpers.go" ]; then
        log "SUCCESS" "Test utilities found"
    else
        log "ERROR" "Test utilities missing"
        return 1
    fi
    
    # Count test files
    local test_files=$(find . -name "*_test.go" -not -path "./vendor/*" | wc -l)
    log "INFO" "Found $test_files test files"
    
    if [ "$test_files" -lt 5 ]; then
        log "ERROR" "Insufficient test files found ($test_files)"
        return 1
    fi
    
    # Run tests and check coverage
    log "INFO" "Running tests and calculating coverage..."
    if go test -coverprofile=coverage.tmp ./... > /dev/null 2>&1; then
        local coverage=$(go tool cover -func=coverage.tmp | grep "total:" | awk '{print $3}' | sed 's/%//' || echo "0")
        rm -f coverage.tmp
        
        log "INFO" "Current test coverage: ${coverage}%"
        
        if (( $(echo "$coverage >= $MIN_COVERAGE_TARGET" | bc -l) )); then
            log "SUCCESS" "Test coverage meets target: ${coverage}% >= ${MIN_COVERAGE_TARGET}%"
        else
            log "ERROR" "Test coverage below target: ${coverage}% < ${MIN_COVERAGE_TARGET}%"
            return 1
        fi
    else
        rm -f coverage.tmp
        log "ERROR" "Tests failed to run"
        return 1
    fi
    
    return 0
}

validate_integration_tests() {
    log "INFO" "Validating integration test suite..."
    
    # Check if integration test setup exists
    if [ -f "${TESTING_DIR}/integration/setup.go" ]; then
        log "SUCCESS" "Integration test setup found"
    else
        log "ERROR" "Integration test setup missing"
        return 1
    fi
    
    # Check if integration test files exist
    local integration_tests=$(find "${TESTING_DIR}/integration" -name "*_test.go" 2>/dev/null | wc -l)
    if [ "$integration_tests" -gt 0 ]; then
        log "SUCCESS" "Integration test files found ($integration_tests files)"
    else
        log "ERROR" "No integration test files found"
        return 1
    fi
    
    # Try to build integration tests (without running them)
    cd "$PROJECT_ROOT"
    if go test -tags=integration -c ./test/integration/... > /dev/null 2>&1; then
        log "SUCCESS" "Integration tests compile successfully"
        rm -f integration.test 2>/dev/null || true
    else
        log "ERROR" "Integration tests compilation failed"
        return 1
    fi
    
    return 0
}

validate_security_testing() {
    log "INFO" "Validating security test automation..."
    
    # Check if security test files exist
    if [ -f "${TESTING_DIR}/security/security_test.go" ]; then
        log "SUCCESS" "Security test suite found"
    else
        log "ERROR" "Security test suite missing"
        return 1
    fi
    
    # Check if OWASP ZAP integration exists
    if [ -f "${TESTING_DIR}/security/zap_integration.sh" ]; then
        log "SUCCESS" "OWASP ZAP integration found"
    else
        log "WARN" "OWASP ZAP integration missing (optional)"
    fi
    
    # Try to build security tests
    cd "$PROJECT_ROOT"
    if go test -c ./test/security/... > /dev/null 2>&1; then
        log "SUCCESS" "Security tests compile successfully"
        rm -f security.test 2>/dev/null || true
    else
        log "ERROR" "Security tests compilation failed"
        return 1
    fi
    
    return 0
}

validate_performance_testing() {
    log "INFO" "Validating performance test framework..."
    
    # Check if performance benchmarks exist
    if [ -f "${TESTING_DIR}/performance/benchmarks_test.go" ]; then
        log "SUCCESS" "Performance benchmarks found"
    else
        log "ERROR" "Performance benchmarks missing"
        return 1
    fi
    
    # Check if load test script exists
    if [ -f "${TESTING_DIR}/performance/load_test.js" ]; then
        log "SUCCESS" "Load test script found"
    else
        log "ERROR" "Load test script missing"
        return 1
    fi
    
    # Check if performance test runner exists
    if [ -f "${TESTING_DIR}/performance/run_performance_tests.sh" ]; then
        log "SUCCESS" "Performance test runner found"
    else
        log "ERROR" "Performance test runner missing"
        return 1
    fi
    
    # Try to run benchmarks (just compilation check)
    cd "$PROJECT_ROOT"
    if go test -c -bench=. ./test/performance/... > /dev/null 2>&1; then
        log "SUCCESS" "Performance benchmarks compile successfully"
        rm -f performance.test 2>/dev/null || true
    else
        log "ERROR" "Performance benchmarks compilation failed"
        return 1
    fi
    
    return 0
}

validate_cicd_pipeline() {
    log "INFO" "Validating CI/CD pipeline deployment..."
    
    # Check if GitHub Actions workflow exists
    if [ -f "${PROJECT_ROOT}/.github/workflows/ci-cd.yml" ]; then
        log "SUCCESS" "GitHub Actions CI/CD workflow found"
    else
        log "ERROR" "GitHub Actions CI/CD workflow missing"
        return 1
    fi
    
    # Check if pre-commit hooks exist
    if [ -f "${PROJECT_ROOT}/.githooks/pre-commit" ]; then
        log "SUCCESS" "Pre-commit hooks found"
    else
        log "ERROR" "Pre-commit hooks missing"
        return 1
    fi
    
    # Validate GitHub Actions workflow syntax (basic check)
    if command -v yamllint &> /dev/null; then
        if yamllint "${PROJECT_ROOT}/.github/workflows/ci-cd.yml" > /dev/null 2>&1; then
            log "SUCCESS" "CI/CD workflow YAML syntax is valid"
        else
            log "ERROR" "CI/CD workflow YAML syntax is invalid"
            return 1
        fi
    else
        log "WARN" "yamllint not available - skipping YAML syntax check"
    fi
    
    return 0
}

validate_test_infrastructure() {
    log "INFO" "Validating test infrastructure..."
    
    # Check test directories
    local test_dirs=(
        "${TESTING_DIR}/unit"
        "${TESTING_DIR}/integration"
        "${TESTING_DIR}/security"
        "${TESTING_DIR}/performance"
        "${TESTING_DIR}/coverage"
    )
    
    for dir in "${test_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log "SUCCESS" "Test directory exists: $(basename "$dir")"
        else
            log "ERROR" "Test directory missing: $(basename "$dir")"
            return 1
        fi
    done
    
    # Check if coverage reports can be generated
    cd "$PROJECT_ROOT"
    if go test -coverprofile=test-coverage.tmp ./... > /dev/null 2>&1; then
        if go tool cover -html=test-coverage.tmp -o test-coverage.html > /dev/null 2>&1; then
            log "SUCCESS" "Coverage report generation works"
            rm -f test-coverage.tmp test-coverage.html
        else
            log "ERROR" "Coverage report generation failed"
            rm -f test-coverage.tmp
            return 1
        fi
    else
        log "ERROR" "Cannot generate coverage data"
        return 1
    fi
    
    return 0
}

validate_quality_gates() {
    log "INFO" "Validating quality gates..."
    
    cd "$PROJECT_ROOT"
    
    # Check if linting tools are configured
    if [ -f "${PROJECT_ROOT}/.golangci.yml" ] || command -v golangci-lint &> /dev/null; then
        log "SUCCESS" "Linting configuration available"
    else
        log "WARN" "Linting configuration not found"
    fi
    
    # Try to run go vet
    if go vet ./... > /dev/null 2>&1; then
        log "SUCCESS" "Go vet passes"
    else
        log "ERROR" "Go vet found issues"
        return 1
    fi
    
    # Try to run go fmt check
    local unformatted=$(gofmt -l . | grep -v vendor | wc -l)
    if [ "$unformatted" -eq 0 ]; then
        log "SUCCESS" "Code formatting is correct"
    else
        log "ERROR" "Code formatting issues found ($unformatted files)"
        return 1
    fi
    
    return 0
}

main() {
    echo -e "${COLOR_CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║             PHASE 3 VALIDATION: TESTING & QUALITY            ║"
    echo "║                        🛡️ THE ARMORY                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
    
    log "INFO" "Starting Phase 3 Testing & Quality validation..."
    
    local validation_passed=true
    
    # Run all validations
    validate_unit_tests || validation_passed=false
    validate_integration_tests || validation_passed=false
    validate_security_testing || validation_passed=false
    validate_performance_testing || validation_passed=false
    validate_cicd_pipeline || validation_passed=false
    validate_test_infrastructure || validation_passed=false
    validate_quality_gates || validation_passed=false
    
    if [ "$validation_passed" = true ]; then
        log "SUCCESS" "🏰 Phase 3 Testing & Quality validation PASSED"
        echo -e "${COLOR_GREEN}"
        echo "✅ All testing frameworks are properly implemented"
        echo "✅ The fortress armory is fully stocked and ready"
        echo -e "${COLOR_NC}"
        exit 0
    else
        log "ERROR" "❌ Phase 3 Testing & Quality validation FAILED"
        echo -e "${COLOR_RED}"
        echo "❌ Some testing components need attention"
        echo "❌ The fortress armory needs better equipment"
        echo -e "${COLOR_NC}"
        exit 1
    fi
}

main "$@"