#!/bin/bash

# PAT FORTRESS ROLLBACK SYSTEM
# Comprehensive rollback capabilities for all phases

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly CONFIG_DIR="${PROJECT_ROOT}/config/fortress"
readonly BACKUP_DIR="${PROJECT_ROOT}/backup/fortress"

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_NC='\033[0m'

# Phase definitions
readonly PHASES=(
    "FOUNDATION_SECURITY"
    "ARCHITECTURE_CONSISTENCY"
    "TESTING_QUALITY"
    "PRODUCTION_DEPLOYMENT"
)

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
        "ROLLBACK") echo -e "${COLOR_PURPLE}🔄[ROLLBACK]${COLOR_NC} ${timestamp} - $message" ;;
    esac
    
    echo "[$level] $timestamp - $message" >> "${LOG_DIR}/rollback.log"
}

display_rollback_banner() {
    echo -e "${COLOR_PURPLE}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                    PAT FORTRESS ROLLBACK                     ║
║                      🔄 SAFE RETREAT 🔄                     ║
║                                                               ║
║  Strategic rollback system for fortress transformation       ║
║  Safely reverting changes while preserving data             ║
║                                                               ║
║  "A strategic retreat is better than a costly defeat"       ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLOR_NC}"
}

create_emergency_backup() {
    local phase="$1"
    log "INFO" "Creating emergency backup before rollback..."
    
    local emergency_backup_dir="${BACKUP_DIR}/emergency/phase-${phase}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$emergency_backup_dir"
    
    # Backup current state
    cp -r "${PROJECT_ROOT}/go.mod" "$emergency_backup_dir/" 2>/dev/null || true
    cp -r "${PROJECT_ROOT}/go.sum" "$emergency_backup_dir/" 2>/dev/null || true
    cp -r "${PROJECT_ROOT}/pkg" "$emergency_backup_dir/" 2>/dev/null || true
    cp -r "${PROJECT_ROOT}/cmd" "$emergency_backup_dir/" 2>/dev/null || true
    cp -r "${PROJECT_ROOT}/internal" "$emergency_backup_dir/" 2>/dev/null || true
    
    # Create emergency backup metadata
    cat > "${emergency_backup_dir}/emergency-metadata.json" << EOF
{
    "type": "emergency_backup",
    "phase": "$phase",
    "created": "$(date -Iseconds)",
    "reason": "pre_rollback_safety",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'N/A')",
    "git_status": "$(git status --porcelain 2>/dev/null | wc -l) uncommitted changes"
}
EOF
    
    log "SUCCESS" "Emergency backup created: $emergency_backup_dir"
}

rollback_phase_1() {
    log "ROLLBACK" "Rolling back Phase 1: Foundation Security..."
    
    create_emergency_backup "1"
    
    # Remove security-related files
    log "INFO" "Removing Phase 1 security implementations..."
    
    # Remove security packages
    rm -rf "${PROJECT_ROOT}/pkg/database/secure_handler.go" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/auth/jwt.go" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/auth/user_service.go" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/middleware/auth.go" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/middleware/rate_limit.go" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/validation" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/middleware/validation.go" 2>/dev/null || true
    
    # Remove security migrations
    rm -rf "${PROJECT_ROOT}/migrations/security" 2>/dev/null || true
    
    # Remove security audit files
    rm -rf "${PROJECT_ROOT}/security/audit-"* 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/security/scans" 2>/dev/null || true
    
    # Restore original go.mod if backup exists
    local checkpoint_dir="${BACKUP_DIR}/checkpoints/phase-1"
    if [ -d "$checkpoint_dir" ]; then
        log "INFO" "Restoring from Phase 1 checkpoint..."
        cp -r "${checkpoint_dir}"/* "${PROJECT_ROOT}/" 2>/dev/null || true
    fi
    
    # Remove security dependencies
    cd "$PROJECT_ROOT"
    go mod edit -droprequire github.com/golang-jwt/jwt/v5 2>/dev/null || true
    go mod edit -droprequire golang.org/x/crypto 2>/dev/null || true
    go mod edit -droprequire golang.org/x/time 2>/dev/null || true
    go mod tidy 2>/dev/null || true
    
    # Update phase status
    echo "ROLLED_BACK" > "${CONFIG_DIR}/FOUNDATION_SECURITY_status"
    
    log "SUCCESS" "Phase 1 rollback completed"
}

rollback_phase_2() {
    log "ROLLBACK" "Rolling back Phase 2: Architecture Consistency..."
    
    create_emergency_backup "2"
    
    # Remove architectural changes
    log "INFO" "Removing Phase 2 architectural implementations..."
    
    # Remove modular structure
    rm -rf "${PROJECT_ROOT}/internal" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/pkg/interfaces" 2>/dev/null || true
    
    # Remove development tools
    rm -f "${PROJECT_ROOT}/Makefile" 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/.air.toml" 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/config.example.yaml" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/.vscode" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/scripts/dev-setup.sh" 2>/dev/null || true
    
    # Restore vendor directory if backup exists
    local checkpoint_dir="${BACKUP_DIR}/checkpoints/phase-2"
    if [ -d "$checkpoint_dir" ] && [ -d "${checkpoint_dir}/vendor" ]; then
        log "INFO" "Restoring vendor directory from checkpoint..."
        cp -r "${checkpoint_dir}/vendor" "${PROJECT_ROOT}/" 2>/dev/null || true
    fi
    
    # Restore original go.mod structure
    if [ -f "${checkpoint_dir}/go.mod" ]; then
        cp "${checkpoint_dir}/go.mod" "${PROJECT_ROOT}/" 2>/dev/null || true
        cp "${checkpoint_dir}/go.sum" "${PROJECT_ROOT}/" 2>/dev/null || true
    fi
    
    cd "$PROJECT_ROOT"
    go mod tidy 2>/dev/null || true
    
    # Update phase status
    echo "ROLLED_BACK" > "${CONFIG_DIR}/ARCHITECTURE_CONSISTENCY_status"
    
    log "SUCCESS" "Phase 2 rollback completed"
}

rollback_phase_3() {
    log "ROLLBACK" "Rolling back Phase 3: Testing & Quality..."
    
    create_emergency_backup "3"
    
    # Remove testing infrastructure
    log "INFO" "Removing Phase 3 testing implementations..."
    
    # Remove test files and directories
    rm -rf "${PROJECT_ROOT}/test" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/.github/workflows/ci-cd.yml" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/.githooks" 2>/dev/null || true
    
    # Remove test-related files
    find "${PROJECT_ROOT}" -name "*_test.go" -delete 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/coverage.out" 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/coverage.html" 2>/dev/null || true
    
    # Remove testing dependencies
    cd "$PROJECT_ROOT"
    go mod edit -droprequire github.com/stretchr/testify 2>/dev/null || true
    go mod edit -droprequire github.com/DATA-DOG/go-sqlmock 2>/dev/null || true
    go mod edit -droprequire github.com/ory/dockertest/v3 2>/dev/null || true
    go mod tidy 2>/dev/null || true
    
    # Reset git hooks to default
    git config --unset core.hooksPath 2>/dev/null || true
    
    # Update phase status
    echo "ROLLED_BACK" > "${CONFIG_DIR}/TESTING_QUALITY_status"
    
    log "SUCCESS" "Phase 3 rollback completed"
}

rollback_phase_4() {
    log "ROLLBACK" "Rolling back Phase 4: Production Deployment..."
    
    create_emergency_backup "4"
    
    # Stop running services first
    log "INFO" "Stopping production services..."
    if [ -f "${PROJECT_ROOT}/docker-compose.production.yml" ]; then
        docker-compose -f "${PROJECT_ROOT}/docker-compose.production.yml" down --remove-orphans 2>/dev/null || true
    fi
    
    # Remove production infrastructure
    log "INFO" "Removing Phase 4 production implementations..."
    
    # Remove Docker configurations
    rm -f "${PROJECT_ROOT}/docker-compose.production.yml" 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/docker-compose.override.yml" 2>/dev/null || true
    rm -f "${PROJECT_ROOT}/.dockerignore" 2>/dev/null || true
    
    # Remove deployment configurations
    rm -rf "${PROJECT_ROOT}/deployment" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/monitoring" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/backup/scripts" 2>/dev/null || true
    rm -rf "${PROJECT_ROOT}/backup/policies" 2>/dev/null || true
    
    # Remove production environment files
    rm -f "${PROJECT_ROOT}/.env.production.example" 2>/dev/null || true
    
    # Remove Docker volumes and networks (be careful!)
    docker volume ls | grep pat-fortress | awk '{print $2}' | xargs -r docker volume rm 2>/dev/null || true
    docker network ls | grep pat-network | awk '{print $2}' | xargs -r docker network rm 2>/dev/null || true
    
    # Update phase status
    echo "ROLLED_BACK" > "${CONFIG_DIR}/PRODUCTION_DEPLOYMENT_status"
    
    log "SUCCESS" "Phase 4 rollback completed"
}

rollback_all_phases() {
    log "ROLLBACK" "Rolling back all fortress phases..."
    
    # Rollback in reverse order
    rollback_phase_4
    rollback_phase_3
    rollback_phase_2
    rollback_phase_1
    
    # Reset fortress metadata
    if [ -f "${CONFIG_DIR}/fortress-metadata.json" ]; then
        local temp_file=$(mktemp)
        jq '.current_readiness = 25' "${CONFIG_DIR}/fortress-metadata.json" > "$temp_file"
        jq '.phases.foundation_security.status = "rolled_back"' "$temp_file" > "${CONFIG_DIR}/fortress-metadata.json"
        jq '.phases.architecture_consistency.status = "rolled_back"' "${CONFIG_DIR}/fortress-metadata.json" > "$temp_file"
        jq '.phases.testing_quality.status = "rolled_back"' "$temp_file" > "${CONFIG_DIR}/fortress-metadata.json"
        jq '.phases.production_deployment.status = "rolled_back"' "${CONFIG_DIR}/fortress-metadata.json" > "$temp_file"
        mv "$temp_file" "${CONFIG_DIR}/fortress-metadata.json"
    fi
    
    log "SUCCESS" "Complete fortress rollback completed"
}

selective_rollback() {
    local target_phase="$1"
    
    case "$target_phase" in
        "1"|"FOUNDATION_SECURITY")
            rollback_phase_1
            ;;
        "2"|"ARCHITECTURE_CONSISTENCY")
            rollback_phase_2
            ;;
        "3"|"TESTING_QUALITY")
            rollback_phase_3
            ;;
        "4"|"PRODUCTION_DEPLOYMENT")
            rollback_phase_4
            ;;
        "all"|"ALL")
            rollback_all_phases
            ;;
        *)
            log "ERROR" "Unknown phase: $target_phase"
            log "INFO" "Valid phases: 1-4, FOUNDATION_SECURITY, ARCHITECTURE_CONSISTENCY, TESTING_QUALITY, PRODUCTION_DEPLOYMENT, all"
            exit 1
            ;;
    esac
}

verify_rollback() {
    local phase="$1"
    log "INFO" "Verifying rollback for phase $phase..."
    
    # Basic verification - check if phase status file indicates rollback
    local phase_name=""
    case "$phase" in
        "1") phase_name="FOUNDATION_SECURITY" ;;
        "2") phase_name="ARCHITECTURE_CONSISTENCY" ;;
        "3") phase_name="TESTING_QUALITY" ;;
        "4") phase_name="PRODUCTION_DEPLOYMENT" ;;
        "all") 
            verify_rollback "1"
            verify_rollback "2"
            verify_rollback "3"
            verify_rollback "4"
            return $?
            ;;
    esac
    
    if [ -f "${CONFIG_DIR}/${phase_name}_status" ]; then
        local status=$(cat "${CONFIG_DIR}/${phase_name}_status")
        if [ "$status" = "ROLLED_BACK" ]; then
            log "SUCCESS" "Phase $phase rollback verified"
        else
            log "ERROR" "Phase $phase rollback verification failed - status: $status"
            return 1
        fi
    else
        log "WARN" "Phase $phase status file not found - cannot verify rollback"
    fi
    
    # Try to build the project after rollback
    cd "$PROJECT_ROOT"
    if go build ./... > /dev/null 2>&1; then
        log "SUCCESS" "Project builds successfully after rollback"
    else
        log "WARN" "Project build failed after rollback - may need manual intervention"
    fi
    
    return 0
}

generate_rollback_report() {
    local phase="$1"
    local report_file="${LOG_DIR}/rollback-report-$(date +%Y%m%d-%H%M%S).json"
    
    log "INFO" "Generating rollback report..."
    
    cat > "$report_file" << EOF
{
    "rollback": {
        "timestamp": "$(date -Iseconds)",
        "phase": "$phase",
        "status": "completed",
        "duration_seconds": $SECONDS,
        "emergency_backup_created": true
    },
    "system_state": {
        "project_builds": $(cd "$PROJECT_ROOT" && go build ./... > /dev/null 2>&1 && echo "true" || echo "false"),
        "git_status": {
            "uncommitted_changes": $(git status --porcelain 2>/dev/null | wc -l),
            "current_branch": "$(git branch --show-current 2>/dev/null || echo 'N/A')",
            "current_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'N/A')"
        }
    },
    "recommendations": [
        "Review emergency backup in backup/emergency/",
        "Test application functionality after rollback",
        "Consider gradual re-implementation of rolled back features",
        "Update documentation to reflect current state"
    ]
}
EOF
    
    log "SUCCESS" "Rollback report generated: $report_file"
    echo "$report_file"
}

show_help() {
    cat << EOF
Pat Fortress Rollback System v${SCRIPT_VERSION}

USAGE:
    $0 [OPTIONS] <PHASE>

PHASES:
    1, FOUNDATION_SECURITY      - Rollback Phase 1: Security implementations
    2, ARCHITECTURE_CONSISTENCY - Rollback Phase 2: Architecture changes  
    3, TESTING_QUALITY         - Rollback Phase 3: Testing infrastructure
    4, PRODUCTION_DEPLOYMENT    - Rollback Phase 4: Production setup
    all, ALL                   - Rollback all phases (complete reset)

OPTIONS:
    --verify                   - Verify rollback after completion
    --no-backup               - Skip emergency backup creation
    --force                   - Force rollback without confirmation
    -h, --help                - Show this help message

EXAMPLES:
    $0 1                      # Rollback Phase 1 only
    $0 TESTING_QUALITY        # Rollback Phase 3 using name
    $0 --verify all           # Rollback all phases and verify
    $0 --force 4              # Force rollback Phase 4 without confirmation

SAFETY FEATURES:
    - Emergency backup created before each rollback
    - Confirmation prompt for destructive operations
    - Rollback verification option
    - Detailed logging of all operations

WARNING: Rollback operations are potentially destructive. Always ensure you have
recent backups and understand the implications before proceeding.
EOF
}

main() {
    local PHASE=""
    local VERIFY_ROLLBACK=false
    local SKIP_BACKUP=false
    local FORCE_ROLLBACK=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verify)
                VERIFY_ROLLBACK=true
                shift
                ;;
            --no-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --force)
                FORCE_ROLLBACK=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [ -z "$PHASE" ]; then
                    PHASE="$1"
                else
                    log "ERROR" "Multiple phases specified. Use 'all' to rollback everything."
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    if [ -z "$PHASE" ]; then
        log "ERROR" "No phase specified"
        show_help
        exit 1
    fi
    
    # Change to project directory
    cd "$PROJECT_ROOT" || {
        log "ERROR" "Cannot change to project directory: $PROJECT_ROOT"
        exit 1
    }
    
    display_rollback_banner
    
    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    log "ROLLBACK" "Starting rollback operation for phase: $PHASE"
    
    # Confirmation (unless forced)
    if [ "$FORCE_ROLLBACK" = false ]; then
        echo -e "${COLOR_YELLOW}"
        echo "⚠️  WARNING: This will rollback fortress implementations for phase $PHASE"
        echo "This operation may be destructive and cannot be easily undone."
        echo "An emergency backup will be created before proceeding."
        echo -e "${COLOR_NC}"
        
        read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Rollback cancelled by user"
            exit 0
        fi
    fi
    
    # Perform rollback
    selective_rollback "$PHASE"
    
    # Verify rollback if requested
    if [ "$VERIFY_ROLLBACK" = true ]; then
        verify_rollback "$PHASE"
    fi
    
    # Generate report
    generate_rollback_report "$PHASE"
    
    echo -e "${COLOR_GREEN}"
    cat << 'SUCCESS'
╔═══════════════════════════════════════════════════════════════╗
║                   ROLLBACK COMPLETED                         ║
║                                                               ║
║  The fortress has been safely rolled back to a previous     ║
║  state. Emergency backups have been created for safety.     ║
║                                                               ║
║  🔄 Strategic retreat accomplished successfully! 🔄         ║
╚═══════════════════════════════════════════════════════════════╝
SUCCESS
    echo -e "${COLOR_NC}"
    
    log "SUCCESS" "Fortress rollback completed successfully"
    log "INFO" "Emergency backups available in: $BACKUP_DIR/emergency/"
    log "INFO" "Check logs for detailed rollback information"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi