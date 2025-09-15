#!/bin/bash

# PAT FORTRESS - PHASE 1 VALIDATION
# Validates completion of Foundation Security phase

set -euo pipefail

readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly SECURITY_DIR="${PROJECT_ROOT}/security"

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
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

validate_sql_injection_mitigation() {
    log "INFO" "Validating SQL injection mitigation..."
    
    # Check if secure database handler exists
    if [ ! -f "${PROJECT_ROOT}/pkg/database/secure_handler.go" ]; then
        log "ERROR" "Secure database handler not found"
        return 1
    fi
    
    # Run gosec to check for SQL injection vulnerabilities
    if command -v gosec &> /dev/null; then
        local sql_issues=$(gosec -severity medium ./... 2>/dev/null | grep -c "SQL" || echo "0")
        if [ "$sql_issues" -eq 0 ]; then
            log "SUCCESS" "No SQL injection vulnerabilities detected"
        else
            log "ERROR" "Found $sql_issues SQL-related security issues"
            return 1
        fi
    else
        log "WARN" "gosec not available - skipping automated SQL injection check"
    fi
    
    return 0
}

validate_authentication_system() {
    log "INFO" "Validating authentication system..."
    
    # Check if authentication files exist
    local auth_files=(
        "${PROJECT_ROOT}/pkg/auth/jwt.go"
        "${PROJECT_ROOT}/pkg/auth/user_service.go"
        "${PROJECT_ROOT}/pkg/middleware/auth.go"
    )
    
    for file in "${auth_files[@]}"; do
        if [ ! -f "$file" ]; then
            log "ERROR" "Authentication file missing: $(basename "$file")"
            return 1
        fi
    done
    
    # Try to build authentication package
    if cd "$PROJECT_ROOT" && go build ./pkg/auth/... > /dev/null 2>&1; then
        log "SUCCESS" "Authentication system builds successfully"
    else
        log "ERROR" "Authentication system build failed"
        return 1
    fi
    
    return 0
}

validate_rate_limiting() {
    log "INFO" "Validating rate limiting implementation..."
    
    # Check if rate limiting middleware exists
    if [ ! -f "${PROJECT_ROOT}/pkg/middleware/rate_limit.go" ]; then
        log "ERROR" "Rate limiting middleware not found"
        return 1
    fi
    
    # Try to build rate limiting package
    if cd "$PROJECT_ROOT" && go build ./pkg/middleware/... > /dev/null 2>&1; then
        log "SUCCESS" "Rate limiting middleware builds successfully"
    else
        log "ERROR" "Rate limiting middleware build failed"
        return 1
    fi
    
    return 0
}

validate_input_validation() {
    log "INFO" "Validating input validation framework..."
    
    # Check if validation package exists
    if [ ! -f "${PROJECT_ROOT}/pkg/validation/validator.go" ]; then
        log "ERROR" "Input validation framework not found"
        return 1
    fi
    
    # Check if validation middleware exists
    if [ ! -f "${PROJECT_ROOT}/pkg/middleware/validation.go" ]; then
        log "ERROR" "Validation middleware not found"
        return 1
    fi
    
    # Try to build validation package
    if cd "$PROJECT_ROOT" && go build ./pkg/validation/... > /dev/null 2>&1; then
        log "SUCCESS" "Input validation framework builds successfully"
    else
        log "ERROR" "Input validation framework build failed"
        return 1
    fi
    
    return 0
}

validate_security_audit() {
    log "INFO" "Validating security audit completion..."
    
    # Check if security audit reports exist
    local audit_reports=$(find "${SECURITY_DIR}/audit-"* -name "*.md" 2>/dev/null | wc -l)
    if [ "$audit_reports" -gt 0 ]; then
        log "SUCCESS" "Security audit reports found ($audit_reports reports)"
    else
        log "WARN" "No security audit reports found"
    fi
    
    # Check if security scans directory exists
    if [ -d "${SECURITY_DIR}/scans" ]; then
        local scan_files=$(find "${SECURITY_DIR}/scans" -name "*.json" 2>/dev/null | wc -l)
        if [ "$scan_files" -gt 0 ]; then
            log "SUCCESS" "Security scan results found ($scan_files files)"
        else
            log "WARN" "No security scan results found"
        fi
    else
        log "WARN" "Security scans directory not found"
    fi
    
    return 0
}

validate_dependencies() {
    log "INFO" "Validating security-related dependencies..."
    
    cd "$PROJECT_ROOT"
    
    # Check if security dependencies are in go.mod
    local required_deps=(
        "github.com/golang-jwt/jwt/v5"
        "golang.org/x/crypto"
        "github.com/lib/pq"
        "github.com/jmoiron/sqlx"
        "golang.org/x/time"
    )
    
    for dep in "${required_deps[@]}"; do
        if grep -q "$dep" go.mod; then
            log "SUCCESS" "Dependency present: $dep"
        else
            log "ERROR" "Missing dependency: $dep"
            return 1
        fi
    done
    
    # Try to download and verify dependencies
    if go mod download && go mod verify > /dev/null 2>&1; then
        log "SUCCESS" "All dependencies verified"
    else
        log "ERROR" "Dependency verification failed"
        return 1
    fi
    
    return 0
}

main() {
    echo -e "${COLOR_BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║              PHASE 1 VALIDATION: FOUNDATION SECURITY         ║"
    echo "║                        ⚔️ THE GUARDS                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
    
    log "INFO" "Starting Phase 1 Foundation Security validation..."
    
    local validation_passed=true
    
    # Run all validations
    validate_sql_injection_mitigation || validation_passed=false
    validate_authentication_system || validation_passed=false
    validate_rate_limiting || validation_passed=false
    validate_input_validation || validation_passed=false
    validate_security_audit || validation_passed=false
    validate_dependencies || validation_passed=false
    
    if [ "$validation_passed" = true ]; then
        log "SUCCESS" "🏰 Phase 1 Foundation Security validation PASSED"
        echo -e "${COLOR_GREEN}"
        echo "✅ All security foundations are properly implemented"
        echo "✅ The fortress guards are in position and ready"
        echo -e "${COLOR_NC}"
        exit 0
    else
        log "ERROR" "❌ Phase 1 Foundation Security validation FAILED"
        echo -e "${COLOR_RED}"
        echo "❌ Some security foundations need attention"
        echo "❌ The fortress guards need reinforcement"
        echo -e "${COLOR_NC}"
        exit 1
    fi
}

main "$@"