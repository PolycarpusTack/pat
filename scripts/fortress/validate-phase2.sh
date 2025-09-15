#!/bin/bash

# PAT FORTRESS - PHASE 2 VALIDATION
# Validates completion of Architecture Consistency phase

set -euo pipefail

readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly ARCHITECTURE_DIR="${PROJECT_ROOT}/architecture"

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
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

validate_architecture_assessment() {
    log "INFO" "Validating architecture assessment completion..."
    
    # Check if architecture assessment exists
    local assessments=$(find "${ARCHITECTURE_DIR}/assessments" -name "architecture-assessment-*.md" 2>/dev/null | wc -l)
    if [ "$assessments" -gt 0 ]; then
        log "SUCCESS" "Architecture assessment found ($assessments assessments)"
    else
        log "ERROR" "No architecture assessment found"
        return 1
    fi
    
    return 0
}

validate_dependency_consolidation() {
    log "INFO" "Validating dependency consolidation..."
    
    cd "$PROJECT_ROOT"
    
    # Check that vendor directory is removed
    if [ -d "vendor" ]; then
        log "ERROR" "vendor/ directory still exists - should be removed"
        return 1
    else
        log "SUCCESS" "vendor/ directory properly removed"
    fi
    
    # Check go.mod exists and has proper module name
    if [ ! -f "go.mod" ]; then
        log "ERROR" "go.mod file not found"
        return 1
    fi
    
    local module_name=$(grep "^module" go.mod | cut -d' ' -f2)
    if [[ "$module_name" == *"fortress"* ]] || [[ "$module_name" != "github.com/pat" ]]; then
        log "SUCCESS" "Module name updated: $module_name"
    else
        log "WARN" "Module name may need updating: $module_name"
    fi
    
    # Check if go.sum exists
    if [ -f "go.sum" ]; then
        log "SUCCESS" "go.sum file exists"
    else
        log "ERROR" "go.sum file not found"
        return 1
    fi
    
    # Verify dependencies are properly managed
    if go mod verify > /dev/null 2>&1; then
        log "SUCCESS" "Dependencies verification passed"
    else
        log "ERROR" "Dependencies verification failed"
        return 1
    fi
    
    return 0
}

validate_service_boundaries() {
    log "INFO" "Validating service boundary definitions..."
    
    # Check if service interfaces exist
    local interface_files=(
        "${PROJECT_ROOT}/pkg/interfaces/auth.go"
        "${PROJECT_ROOT}/pkg/interfaces/email.go"
        "${PROJECT_ROOT}/pkg/interfaces/storage.go"
    )
    
    for file in "${interface_files[@]}"; do
        if [ -f "$file" ]; then
            log "SUCCESS" "Service interface found: $(basename "$file")"
        else
            log "ERROR" "Service interface missing: $(basename "$file")"
            return 1
        fi
    done
    
    # Try to build interfaces package
    if go build ./pkg/interfaces/... > /dev/null 2>&1; then
        log "SUCCESS" "Service interfaces build successfully"
    else
        log "ERROR" "Service interfaces build failed"
        return 1
    fi
    
    return 0
}

validate_modular_structure() {
    log "INFO" "Validating modular structure implementation..."
    
    # Check if modular directories exist
    local modular_dirs=(
        "${PROJECT_ROOT}/internal/app"
        "${PROJECT_ROOT}/internal/config"
        "${PROJECT_ROOT}/internal/services"
        "${PROJECT_ROOT}/internal/api"
        "${PROJECT_ROOT}/internal/infrastructure"
    )
    
    for dir in "${modular_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log "SUCCESS" "Modular directory exists: $(basename "$dir")"
        else
            log "ERROR" "Modular directory missing: $(basename "$dir")"
            return 1
        fi
    done
    
    # Check if application bootstrap exists
    if [ -f "${PROJECT_ROOT}/internal/app/app.go" ]; then
        log "SUCCESS" "Application bootstrap exists"
    else
        log "ERROR" "Application bootstrap missing"
        return 1
    fi
    
    # Check if configuration management exists
    if [ -f "${PROJECT_ROOT}/internal/config/config.go" ]; then
        log "SUCCESS" "Configuration management exists"
    else
        log "ERROR" "Configuration management missing"
        return 1
    fi
    
    return 0
}

validate_development_environment() {
    log "INFO" "Validating development environment standardization..."
    
    # Check if Makefile exists
    if [ -f "${PROJECT_ROOT}/Makefile" ]; then
        log "SUCCESS" "Makefile exists"
    else
        log "ERROR" "Makefile missing"
        return 1
    fi
    
    # Check if Air configuration exists
    if [ -f "${PROJECT_ROOT}/.air.toml" ]; then
        log "SUCCESS" "Air hot-reload configuration exists"
    else
        log "WARN" "Air configuration missing (optional)"
    fi
    
    # Check if example configuration exists
    if [ -f "${PROJECT_ROOT}/config.example.yaml" ]; then
        log "SUCCESS" "Example configuration exists"
    else
        log "ERROR" "Example configuration missing"
        return 1
    fi
    
    # Check if VS Code settings exist
    if [ -f "${PROJECT_ROOT}/.vscode/settings.json" ]; then
        log "SUCCESS" "VS Code settings exist"
    else
        log "WARN" "VS Code settings missing (optional)"
    fi
    
    # Check if development setup script exists
    if [ -f "${PROJECT_ROOT}/scripts/dev-setup.sh" ]; then
        log "SUCCESS" "Development setup script exists"
    else
        log "ERROR" "Development setup script missing"
        return 1
    fi
    
    return 0
}

validate_build_system() {
    log "INFO" "Validating build system..."
    
    cd "$PROJECT_ROOT"
    
    # Try to run make commands
    if make --dry-run build > /dev/null 2>&1; then
        log "SUCCESS" "Make build target exists"
    else
        log "ERROR" "Make build target missing or invalid"
        return 1
    fi
    
    if make --dry-run test > /dev/null 2>&1; then
        log "SUCCESS" "Make test target exists"
    else
        log "ERROR" "Make test target missing or invalid"
        return 1
    fi
    
    # Try to build the project
    if go build ./... > /dev/null 2>&1; then
        log "SUCCESS" "Project builds successfully"
    else
        log "ERROR" "Project build failed"
        return 1
    fi
    
    return 0
}

main() {
    echo -e "${COLOR_PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║            PHASE 2 VALIDATION: ARCHITECTURE CONSISTENCY      ║"
    echo "║                      👁️ THE WATCHTOWERS                      ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
    
    log "INFO" "Starting Phase 2 Architecture Consistency validation..."
    
    local validation_passed=true
    
    # Run all validations
    validate_architecture_assessment || validation_passed=false
    validate_dependency_consolidation || validation_passed=false
    validate_service_boundaries || validation_passed=false
    validate_modular_structure || validation_passed=false
    validate_development_environment || validation_passed=false
    validate_build_system || validation_passed=false
    
    if [ "$validation_passed" = true ]; then
        log "SUCCESS" "🏰 Phase 2 Architecture Consistency validation PASSED"
        echo -e "${COLOR_GREEN}"
        echo "✅ All architectural foundations are properly structured"
        echo "✅ The fortress watchtowers provide clear oversight"
        echo -e "${COLOR_NC}"
        exit 0
    else
        log "ERROR" "❌ Phase 2 Architecture Consistency validation FAILED"
        echo -e "${COLOR_RED}"
        echo "❌ Some architectural elements need attention"
        echo "❌ The fortress watchtowers need better positioning"
        echo -e "${COLOR_NC}"
        exit 1
    fi
}

main "$@"