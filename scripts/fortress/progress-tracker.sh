#!/bin/bash

# PAT FORTRESS PROGRESS TRACKER
# Real-time progress tracking and reporting system

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly CONFIG_DIR="${PROJECT_ROOT}/config/fortress"
readonly REPORTS_DIR="${PROJECT_ROOT}/reports/fortress"

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_WHITE='\033[1;37m'
readonly COLOR_NC='\033[0m'

# Fortress symbols
readonly SYMBOL_FORTRESS="🏰"
readonly SYMBOL_GUARD="⚔️"
readonly SYMBOL_WATCHTOWER="👁️"
readonly SYMBOL_ARMORY="🛡️"
readonly SYMBOL_RAMPARTS="🏗️"
readonly SYMBOL_PROGRESS="📊"

# Phase definitions
readonly PHASES=(
    "FOUNDATION_SECURITY"
    "ARCHITECTURE_CONSISTENCY" 
    "TESTING_QUALITY"
    "PRODUCTION_DEPLOYMENT"
)

declare -A PHASE_SYMBOLS=(
    ["FOUNDATION_SECURITY"]="$SYMBOL_GUARD"
    ["ARCHITECTURE_CONSISTENCY"]="$SYMBOL_WATCHTOWER"
    ["TESTING_QUALITY"]="$SYMBOL_ARMORY"
    ["PRODUCTION_DEPLOYMENT"]="$SYMBOL_RAMPARTS"
)

declare -A PHASE_COLORS=(
    ["FOUNDATION_SECURITY"]="$COLOR_BLUE"
    ["ARCHITECTURE_CONSISTENCY"]="$COLOR_PURPLE"
    ["TESTING_QUALITY"]="$COLOR_CYAN"
    ["PRODUCTION_DEPLOYMENT"]="$COLOR_WHITE"
)

# ============================================================================
# LOGGING AND UTILITIES
# ============================================================================

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
        "PROGRESS") echo -e "${COLOR_CYAN}${SYMBOL_PROGRESS}[PROGRESS]${COLOR_NC} ${timestamp} - $message" ;;
    esac
    
    echo "[$level] $timestamp - $message" >> "${LOG_DIR}/progress-tracker.log"
}

create_directories() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$REPORTS_DIR"
    mkdir -p "${REPORTS_DIR}/daily"
    mkdir -p "${REPORTS_DIR}/metrics"
}

# ============================================================================
# PROGRESS CALCULATION
# ============================================================================

get_phase_status() {
    local phase="$1"
    
    if [ -f "${CONFIG_DIR}/${phase}_status" ]; then
        cat "${CONFIG_DIR}/${phase}_status"
    else
        echo "PENDING"
    fi
}

calculate_overall_progress() {
    local completed_phases=0
    local total_phases=${#PHASES[@]}
    
    for phase in "${PHASES[@]}"; do
        local status=$(get_phase_status "$phase")
        if [ "$status" = "COMPLETED" ]; then
            ((completed_phases++))
        fi
    done
    
    # Base readiness is 25%, each completed phase adds 18.75%
    local base_readiness=25
    local phase_contribution=18.75
    local current_progress=$(echo "$base_readiness + ($completed_phases * $phase_contribution)" | bc -l)
    
    printf "%.0f\n" "$current_progress"
}

get_phase_progress() {
    local phase="$1"
    local status=$(get_phase_status "$phase")
    
    case "$status" in
        "PENDING") echo "0" ;;
        "IN_PROGRESS") echo "50" ;;
        "COMPLETED") echo "100" ;;
        "FAILED") echo "25" ;;
        "ROLLED_BACK") echo "0" ;;
        *) echo "0" ;;
    esac
}

# ============================================================================
# PROGRESS DISPLAY
# ============================================================================

display_progress_bar() {
    local percentage="$1"
    local width=50
    local filled_chars=$(( percentage * width / 100 ))
    local empty_chars=$(( width - filled_chars ))
    
    # Create progress bar
    printf "["
    
    # Filled portion (green)
    printf "${COLOR_GREEN}"
    for ((i=0; i<filled_chars; i++)); do
        printf "█"
    done
    
    # Empty portion (dark)
    printf "${COLOR_NC}"
    for ((i=0; i<empty_chars; i++)); do
        printf "░"
    done
    
    printf "] ${COLOR_WHITE}%3d%%${COLOR_NC}" "$percentage"
}

display_fortress_status() {
    local overall_progress=$(calculate_overall_progress)
    
    echo -e "${COLOR_PURPLE}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                 PAT FORTRESS PROGRESS TRACKER                ║
║                       📊 STATUS REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLOR_NC}"
    
    # Overall progress
    echo -e "\n${COLOR_WHITE}${SYMBOL_FORTRESS} OVERALL FORTRESS PROGRESS${COLOR_NC}"
    echo -n "Production Readiness: "
    display_progress_bar "$overall_progress"
    echo -e "\n"
    
    # Individual phases
    echo -e "${COLOR_WHITE}📋 PHASE BREAKDOWN${COLOR_NC}"
    echo "╭─────────────────────────────────────────────────────────────╮"
    
    local phase_num=1
    for phase in "${PHASES[@]}"; do
        local status=$(get_phase_status "$phase")
        local progress=$(get_phase_progress "$phase")
        local symbol="${PHASE_SYMBOLS[$phase]}"
        local color="${PHASE_COLORS[$phase]}"
        
        # Format phase name
        local phase_display=$(echo "$phase" | tr '_' ' ' | tr '[:upper:]' '[:lower:]')
        phase_display=$(echo "${phase_display^}")
        
        # Status symbol
        local status_symbol=""
        case "$status" in
            "PENDING")     status_symbol="⏳" ;;
            "IN_PROGRESS") status_symbol="🔄" ;;
            "COMPLETED")   status_symbol="✅" ;;
            "FAILED")      status_symbol="❌" ;;
            "ROLLED_BACK") status_symbol="↩️" ;;
        esac
        
        printf "│ ${color}${symbol}${COLOR_NC} Phase %d: %-25s %s %-12s " \
               "$phase_num" "$phase_display" "$status_symbol" "$status"
        
        display_progress_bar "$progress"
        echo " │"
        
        ((phase_num++))
    done
    
    echo "╰─────────────────────────────────────────────────────────────╯"
}

display_detailed_phase_status() {
    local phase="$1"
    local status=$(get_phase_status "$phase")
    local progress=$(get_phase_progress "$phase")
    local symbol="${PHASE_SYMBOLS[$phase]}"
    local color="${PHASE_COLORS[$phase]}"
    
    echo -e "\n${color}${symbol} PHASE DETAILS: $(echo "$phase" | tr '_' ' ')${COLOR_NC}"
    echo "════════════════════════════════════════════════════════"
    echo -e "Status: ${COLOR_WHITE}$status${COLOR_NC}"
    echo -n "Progress: "
    display_progress_bar "$progress"
    echo
    
    # Phase-specific details
    case "$phase" in
        "FOUNDATION_SECURITY")
            check_security_implementations
            ;;
        "ARCHITECTURE_CONSISTENCY")
            check_architecture_implementations
            ;;
        "TESTING_QUALITY")
            check_testing_implementations
            ;;
        "PRODUCTION_DEPLOYMENT")
            check_deployment_implementations
            ;;
    esac
}

check_security_implementations() {
    echo -e "\n${COLOR_BLUE}Security Implementation Status:${COLOR_NC}"
    
    # Check if security files exist
    local security_files=(
        "pkg/database/secure_handler.go:Database Security"
        "pkg/auth/jwt.go:JWT Authentication"
        "pkg/middleware/auth.go:Auth Middleware"
        "pkg/middleware/rate_limit.go:Rate Limiting"
        "pkg/validation/validator.go:Input Validation"
    )
    
    for file_desc in "${security_files[@]}"; do
        local file_path=$(echo "$file_desc" | cut -d':' -f1)
        local description=$(echo "$file_desc" | cut -d':' -f2)
        
        if [ -f "${PROJECT_ROOT}/$file_path" ]; then
            echo -e "  ✅ $description"
        else
            echo -e "  ❌ $description"
        fi
    done
    
    # Check dependencies
    if grep -q "github.com/golang-jwt/jwt/v5" "${PROJECT_ROOT}/go.mod" 2>/dev/null; then
        echo -e "  ✅ Security Dependencies"
    else
        echo -e "  ❌ Security Dependencies"
    fi
}

check_architecture_implementations() {
    echo -e "\n${COLOR_PURPLE}Architecture Implementation Status:${COLOR_NC}"
    
    # Check modular structure
    local arch_dirs=(
        "internal/app:Application Bootstrap"
        "internal/config:Configuration Management"
        "internal/services:Service Layer"
        "pkg/interfaces:Service Interfaces"
    )
    
    for dir_desc in "${arch_dirs[@]}"; do
        local dir_path=$(echo "$dir_desc" | cut -d':' -f1)
        local description=$(echo "$dir_desc" | cut -d':' -f2)
        
        if [ -d "${PROJECT_ROOT}/$dir_path" ]; then
            echo -e "  ✅ $description"
        else
            echo -e "  ❌ $description"
        fi
    done
    
    # Check development tools
    if [ -f "${PROJECT_ROOT}/Makefile" ]; then
        echo -e "  ✅ Build System"
    else
        echo -e "  ❌ Build System"
    fi
    
    # Check vendor removal
    if [ ! -d "${PROJECT_ROOT}/vendor" ]; then
        echo -e "  ✅ Dependency Consolidation"
    else
        echo -e "  ❌ Dependency Consolidation (vendor/ still exists)"
    fi
}

check_testing_implementations() {
    echo -e "\n${COLOR_CYAN}Testing Implementation Status:${COLOR_NC}"
    
    # Check test directories
    local test_dirs=(
        "test/unit:Unit Tests"
        "test/integration:Integration Tests"
        "test/security:Security Tests"
        "test/performance:Performance Tests"
    )
    
    for dir_desc in "${test_dirs[@]}"; do
        local dir_path=$(echo "$dir_desc" | cut -d':' -f1)
        local description=$(echo "$dir_desc" | cut -d':' -f2)
        
        if [ -d "${PROJECT_ROOT}/$dir_path" ]; then
            echo -e "  ✅ $description"
        else
            echo -e "  ❌ $description"
        fi
    done
    
    # Check CI/CD
    if [ -f "${PROJECT_ROOT}/.github/workflows/ci-cd.yml" ]; then
        echo -e "  ✅ CI/CD Pipeline"
    else
        echo -e "  ❌ CI/CD Pipeline"
    fi
    
    # Check test coverage
    if [ -d "${PROJECT_ROOT}/test/coverage" ]; then
        cd "$PROJECT_ROOT"
        if go test -coverprofile=temp-coverage.out ./... >/dev/null 2>&1; then
            local coverage=$(go tool cover -func=temp-coverage.out | grep "total:" | awk '{print $3}' | sed 's/%//' || echo "0")
            rm -f temp-coverage.out
            echo -e "  📊 Test Coverage: ${coverage}%"
        else
            echo -e "  ❌ Test Coverage: Unable to calculate"
        fi
    else
        echo -e "  ❌ Test Coverage: Not configured"
    fi
}

check_deployment_implementations() {
    echo -e "\n${COLOR_WHITE}Deployment Implementation Status:${COLOR_NC}"
    
    # Check deployment files
    local deploy_files=(
        "docker-compose.production.yml:Production Docker Compose"
        "deployment/scripts/deploy-pat-fortress.sh:Deployment Automation"
        "monitoring/prometheus/prometheus.yml:Monitoring Configuration"
        "backup/scripts/backup-database.sh:Backup System"
    )
    
    for file_desc in "${deploy_files[@]}"; do
        local file_path=$(echo "$file_desc" | cut -d':' -f1)
        local description=$(echo "$file_desc" | cut -d':' -f2)
        
        if [ -f "${PROJECT_ROOT}/$file_path" ]; then
            echo -e "  ✅ $description"
        else
            echo -e "  ❌ $description"
        fi
    done
    
    # Check Docker
    if command -v docker >/dev/null 2>&1; then
        echo -e "  ✅ Docker Available"
    else
        echo -e "  ❌ Docker Not Available"
    fi
}

# ============================================================================
# METRICS AND ANALYTICS
# ============================================================================

generate_progress_metrics() {
    local overall_progress=$(calculate_overall_progress)
    local timestamp=$(date -Iseconds)
    
    local metrics_file="${REPORTS_DIR}/metrics/progress-$(date +%Y%m%d-%H%M%S).json"
    
    # Calculate phase progress
    local phase_metrics=""
    local first=true
    
    for phase in "${PHASES[@]}"; do
        [ "$first" = true ] && first=false || phase_metrics+=","
        
        local status=$(get_phase_status "$phase")
        local progress=$(get_phase_progress "$phase")
        
        phase_metrics+="
        \"$(echo "$phase" | tr '[:upper:]' '[:lower:]')\": {
            \"status\": \"$status\",
            \"progress_percentage\": $progress,
            \"last_updated\": \"$(date -r "${CONFIG_DIR}/${phase}_status" -Iseconds 2>/dev/null || echo "$timestamp")\""
        }"
    done
    
    # Generate comprehensive metrics
    cat > "$metrics_file" << EOF
{
    "fortress_progress": {
        "timestamp": "$timestamp",
        "overall_readiness_percentage": $overall_progress,
        "transformation_days_elapsed": $(calculate_days_elapsed),
        "total_transformation_days": 34,
        "phases": {$phase_metrics
        },
        "quality_metrics": {
            "test_coverage_percentage": $(get_test_coverage),
            "security_vulnerabilities": $(get_security_vulnerabilities_count),
            "code_quality_score": $(get_code_quality_score),
            "deployment_readiness": $(get_deployment_readiness)
        },
        "technical_debt": {
            "go_vet_issues": $(get_go_vet_issues),
            "gofmt_issues": $(get_gofmt_issues),
            "unused_dependencies": $(get_unused_dependencies_count)
        }
    }
}
EOF
    
    echo "$metrics_file"
}

calculate_days_elapsed() {
    if [ -f "${CONFIG_DIR}/fortress-metadata.json" ]; then
        local start_date=$(jq -r '.initialized' "${CONFIG_DIR}/fortress-metadata.json" 2>/dev/null)
        if [ "$start_date" != "null" ] && [ -n "$start_date" ]; then
            local start_timestamp=$(date -d "$start_date" +%s 2>/dev/null || echo "0")
            local current_timestamp=$(date +%s)
            echo $(( (current_timestamp - start_timestamp) / 86400 ))
        else
            echo "0"
        fi
    else
        echo "0"
    fi
}

get_test_coverage() {
    cd "$PROJECT_ROOT"
    if go test -coverprofile=temp-coverage.out ./... >/dev/null 2>&1; then
        local coverage=$(go tool cover -func=temp-coverage.out | grep "total:" | awk '{print $3}' | sed 's/%//' || echo "0")
        rm -f temp-coverage.out
        echo "$coverage"
    else
        echo "0"
    fi
}

get_security_vulnerabilities_count() {
    if command -v gosec >/dev/null 2>&1; then
        cd "$PROJECT_ROOT"
        gosec -quiet -severity medium ./... 2>/dev/null | grep -c "Severity:" || echo "0"
    else
        echo "0"
    fi
}

get_code_quality_score() {
    cd "$PROJECT_ROOT"
    local score=100
    
    # Deduct for go vet issues
    local vet_issues=$(go vet ./... 2>&1 | wc -l || echo "0")
    score=$((score - vet_issues * 2))
    
    # Deduct for formatting issues
    local fmt_issues=$(gofmt -l . | grep -v vendor | wc -l || echo "0")
    score=$((score - fmt_issues * 1))
    
    # Ensure score doesn't go below 0
    [ $score -lt 0 ] && score=0
    [ $score -gt 100 ] && score=100
    
    echo "$score"
}

get_deployment_readiness() {
    local readiness=0
    
    # Check essential deployment files
    [ -f "${PROJECT_ROOT}/docker-compose.production.yml" ] && readiness=$((readiness + 25))
    [ -f "${PROJECT_ROOT}/deployment/scripts/deploy-pat-fortress.sh" ] && readiness=$((readiness + 25))
    [ -d "${PROJECT_ROOT}/monitoring" ] && readiness=$((readiness + 25))
    [ -d "${PROJECT_ROOT}/backup/scripts" ] && readiness=$((readiness + 25))
    
    echo "$readiness"
}

get_go_vet_issues() {
    cd "$PROJECT_ROOT"
    go vet ./... 2>&1 | wc -l || echo "0"
}

get_gofmt_issues() {
    cd "$PROJECT_ROOT"
    gofmt -l . | grep -v vendor | wc -l || echo "0"
}

get_unused_dependencies_count() {
    # This is a simplified check - in practice, would use tools like go mod tidy
    echo "0"
}

# ============================================================================
# REPORTING
# ============================================================================

generate_daily_report() {
    local report_file="${REPORTS_DIR}/daily/daily-report-$(date +%Y%m%d).md"
    local overall_progress=$(calculate_overall_progress)
    local days_elapsed=$(calculate_days_elapsed)
    
    cat > "$report_file" << EOF
# Pat Fortress Daily Progress Report

**Date**: $(date)  
**Days Elapsed**: $days_elapsed / 34  
**Overall Progress**: ${overall_progress}% Production Ready

## Phase Status Summary

$(for phase in "${PHASES[@]}"; do
    local status=$(get_phase_status "$phase")
    local progress=$(get_phase_progress "$phase")
    local symbol="${PHASE_SYMBOLS[$phase]}"
    
    echo "### $symbol $(echo "$phase" | tr '_' ' ' | tr '[:upper:]' '[:lower:]' | sed 's/.*/\u&/')"
    echo "- **Status**: $status"
    echo "- **Progress**: ${progress}%"
    echo ""
done)

## Quality Metrics

- **Test Coverage**: $(get_test_coverage)%
- **Security Issues**: $(get_security_vulnerabilities_count)
- **Code Quality Score**: $(get_code_quality_score)/100
- **Deployment Readiness**: $(get_deployment_readiness)%

## Technical Health

- **Go Vet Issues**: $(get_go_vet_issues)
- **Code Formatting Issues**: $(get_gofmt_issues)
- **Build Status**: $(cd "$PROJECT_ROOT" && go build ./... >/dev/null 2>&1 && echo "✅ Success" || echo "❌ Failed")

## Next Steps

$(if [ "$overall_progress" -lt 100 ]; then
    echo "### Pending Actions"
    for phase in "${PHASES[@]}"; do
        local status=$(get_phase_status "$phase")
        if [ "$status" != "COMPLETED" ]; then
            echo "- Complete Phase: $(echo "$phase" | tr '_' ' ' | tr '[:upper:]' '[:lower:]')"
        fi
    done
else
    echo "🎉 **All phases completed! Pat Fortress is production ready!**"
fi)

---
*Report generated automatically by Pat Fortress Progress Tracker v${SCRIPT_VERSION}*
EOF

    echo "$report_file"
}

# ============================================================================
# CONTINUOUS MONITORING
# ============================================================================

start_continuous_monitoring() {
    local interval="${1:-60}" # seconds
    
    log "PROGRESS" "Starting continuous monitoring (interval: ${interval}s)"
    
    while true; do
        clear
        display_fortress_status
        
        echo -e "\n${COLOR_YELLOW}⏱️  Monitoring active (refresh every ${interval}s) - Press Ctrl+C to stop${COLOR_NC}"
        echo -e "${COLOR_BLUE}📊 Last updated: $(date)${COLOR_NC}"
        
        sleep "$interval"
    done
}

# ============================================================================
# MAIN FUNCTIONALITY
# ============================================================================

show_help() {
    cat << EOF
Pat Fortress Progress Tracker v${SCRIPT_VERSION}

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    status                     - Show current fortress status (default)
    detailed <phase>          - Show detailed phase status
    metrics                   - Generate progress metrics JSON
    report                    - Generate daily progress report
    monitor [interval]        - Start continuous monitoring
    watch                     - Alias for monitor with 30s interval

PHASES (for detailed command):
    1, foundation, security          - Foundation Security
    2, architecture, consistency     - Architecture Consistency  
    3, testing, quality              - Testing & Quality
    4, production, deployment        - Production Deployment

OPTIONS:
    --json                    - Output in JSON format (where applicable)
    --quiet                   - Minimal output
    --no-color               - Disable colored output
    -h, --help               - Show this help message

EXAMPLES:
    $0                        # Show current status
    $0 status                 # Same as above
    $0 detailed 1             # Show Phase 1 details
    $0 monitor 30             # Monitor with 30s refresh
    $0 metrics --json         # Generate JSON metrics
    $0 report                 # Generate daily report

The progress tracker provides real-time insights into the Pat Fortress
transformation, including phase status, quality metrics, and readiness indicators.
EOF
}

main() {
    local COMMAND="status"
    local PHASE=""
    local JSON_OUTPUT=false
    local QUIET=false
    local MONITOR_INTERVAL=60
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            status)
                COMMAND="status"
                shift
                ;;
            detailed)
                COMMAND="detailed"
                PHASE="$2"
                shift 2
                ;;
            metrics)
                COMMAND="metrics"
                shift
                ;;
            report)
                COMMAND="report"
                shift
                ;;
            monitor)
                COMMAND="monitor"
                if [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]]; then
                    MONITOR_INTERVAL="$2"
                    shift
                fi
                shift
                ;;
            watch)
                COMMAND="monitor"
                MONITOR_INTERVAL=30
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            --no-color)
                # Disable colors by resetting color variables
                COLOR_RED=""
                COLOR_GREEN=""
                COLOR_YELLOW=""
                COLOR_BLUE=""
                COLOR_PURPLE=""
                COLOR_CYAN=""
                COLOR_WHITE=""
                COLOR_NC=""
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Change to project directory
    cd "$PROJECT_ROOT" || {
        log "ERROR" "Cannot change to project directory: $PROJECT_ROOT"
        exit 1
    }
    
    create_directories
    
    # Execute command
    case "$COMMAND" in
        "status")
            if [ "$JSON_OUTPUT" = true ]; then
                generate_progress_metrics
            else
                display_fortress_status
            fi
            ;;
        "detailed")
            if [ -z "$PHASE" ]; then
                log "ERROR" "Phase required for detailed command"
                exit 1
            fi
            
            # Normalize phase name
            case "${PHASE,,}" in
                "1"|"foundation"|"security") PHASE="FOUNDATION_SECURITY" ;;
                "2"|"architecture"|"consistency") PHASE="ARCHITECTURE_CONSISTENCY" ;;
                "3"|"testing"|"quality") PHASE="TESTING_QUALITY" ;;
                "4"|"production"|"deployment") PHASE="PRODUCTION_DEPLOYMENT" ;;
                *) log "ERROR" "Unknown phase: $PHASE"; exit 1 ;;
            esac
            
            display_detailed_phase_status "$PHASE"
            ;;
        "metrics")
            local metrics_file=$(generate_progress_metrics)
            if [ "$QUIET" = false ]; then
                log "SUCCESS" "Progress metrics generated: $metrics_file"
            fi
            [ "$JSON_OUTPUT" = true ] && cat "$metrics_file"
            ;;
        "report")
            local report_file=$(generate_daily_report)
            if [ "$QUIET" = false ]; then
                log "SUCCESS" "Daily report generated: $report_file"
                echo -e "\n${COLOR_CYAN}Preview:${COLOR_NC}"
                head -20 "$report_file"
            fi
            ;;
        "monitor")
            start_continuous_monitoring "$MONITOR_INTERVAL"
            ;;
        *)
            log "ERROR" "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi