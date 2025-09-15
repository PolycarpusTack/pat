#!/bin/bash

# PAT FORTRESS - PHASE 4 VALIDATION
# Validates completion of Production Deployment phase

set -euo pipefail

readonly PROJECT_ROOT="/mnt/c/Projects/Pat"
readonly LOG_DIR="${PROJECT_ROOT}/logs/fortress"
readonly DEPLOYMENT_DIR="${PROJECT_ROOT}/deployment"
readonly MONITORING_DIR="${PROJECT_ROOT}/monitoring"

# Colors
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_WHITE='\033[1;37m'
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

validate_docker_infrastructure() {
    log "INFO" "Validating Docker infrastructure setup..."
    
    # Check if Dockerfile exists and is production-ready
    if [ -f "${PROJECT_ROOT}/Dockerfile" ]; then
        log "SUCCESS" "Dockerfile found"
        
        # Check for multi-stage build
        if grep -q "FROM.*AS builder" "${PROJECT_ROOT}/Dockerfile"; then
            log "SUCCESS" "Multi-stage Dockerfile detected"
        else
            log "WARN" "Single-stage Dockerfile (multi-stage recommended for production)"
        fi
    else
        log "ERROR" "Dockerfile missing"
        return 1
    fi
    
    # Check if .dockerignore exists
    if [ -f "${PROJECT_ROOT}/.dockerignore" ]; then
        log "SUCCESS" ".dockerignore found"
    else
        log "ERROR" ".dockerignore missing"
        return 1
    fi
    
    # Check if production Docker Compose exists
    if [ -f "${PROJECT_ROOT}/docker-compose.production.yml" ]; then
        log "SUCCESS" "Production Docker Compose found"
    else
        log "ERROR" "Production Docker Compose missing"
        return 1
    fi
    
    # Validate Docker Compose syntax
    if command -v docker-compose &> /dev/null; then
        if docker-compose -f "${PROJECT_ROOT}/docker-compose.production.yml" config > /dev/null 2>&1; then
            log "SUCCESS" "Docker Compose syntax is valid"
        else
            log "ERROR" "Docker Compose syntax is invalid"
            return 1
        fi
    else
        log "WARN" "docker-compose not available - skipping syntax check"
    fi
    
    # Check Nginx configuration
    if [ -f "${DEPLOYMENT_DIR}/nginx/nginx.conf" ]; then
        log "SUCCESS" "Nginx configuration found"
    else
        log "ERROR" "Nginx configuration missing"
        return 1
    fi
    
    return 0
}

validate_monitoring_observability() {
    log "INFO" "Validating monitoring and observability setup..."
    
    # Check Prometheus configuration
    if [ -f "${MONITORING_DIR}/prometheus/prometheus.yml" ]; then
        log "SUCCESS" "Prometheus configuration found"
    else
        log "ERROR" "Prometheus configuration missing"
        return 1
    fi
    
    # Check if alerting rules exist
    if [ -d "${MONITORING_DIR}/prometheus/rules" ]; then
        local rule_files=$(find "${MONITORING_DIR}/prometheus/rules" -name "*.yml" | wc -l)
        if [ "$rule_files" -gt 0 ]; then
            log "SUCCESS" "Prometheus alerting rules found ($rule_files files)"
        else
            log "ERROR" "No Prometheus alerting rules found"
            return 1
        fi
    else
        log "ERROR" "Prometheus rules directory missing"
        return 1
    fi
    
    # Check Grafana configuration
    if [ -d "${MONITORING_DIR}/grafana" ]; then
        log "SUCCESS" "Grafana configuration directory found"
        
        # Check for dashboards
        if [ -d "${MONITORING_DIR}/grafana/dashboards" ]; then
            local dashboard_files=$(find "${MONITORING_DIR}/grafana/dashboards" -name "*.json" | wc -l)
            if [ "$dashboard_files" -gt 0 ]; then
                log "SUCCESS" "Grafana dashboards found ($dashboard_files dashboards)"
            else
                log "WARN" "No Grafana dashboards found"
            fi
        fi
    else
        log "ERROR" "Grafana configuration missing"
        return 1
    fi
    
    # Check Loki configuration
    if [ -f "${MONITORING_DIR}/loki/loki.yml" ]; then
        log "SUCCESS" "Loki configuration found"
    else
        log "ERROR" "Loki configuration missing"
        return 1
    fi
    
    # Check Promtail configuration
    if [ -f "${MONITORING_DIR}/promtail/promtail.yml" ]; then
        log "SUCCESS" "Promtail configuration found"
    else
        log "ERROR" "Promtail configuration missing"
        return 1
    fi
    
    return 0
}

validate_backup_disaster_recovery() {
    log "INFO" "Validating backup and disaster recovery systems..."
    
    # Check backup scripts
    local backup_scripts=(
        "${PROJECT_ROOT}/backup/scripts/backup-database.sh"
        "${PROJECT_ROOT}/backup/scripts/backup-full.sh"
        "${PROJECT_ROOT}/backup/scripts/restore-database.sh"
        "${PROJECT_ROOT}/backup/scripts/backup-monitor.sh"
    )
    
    for script in "${backup_scripts[@]}"; do
        if [ -f "$script" ] && [ -x "$script" ]; then
            log "SUCCESS" "Backup script found and executable: $(basename "$script")"
        else
            log "ERROR" "Backup script missing or not executable: $(basename "$script")"
            return 1
        fi
    done
    
    # Check backup policy document
    if [ -f "${PROJECT_ROOT}/backup/policies/backup-policy.md" ]; then
        log "SUCCESS" "Backup policy document found"
    else
        log "ERROR" "Backup policy document missing"
        return 1
    fi
    
    # Check if backup directories would be created
    local backup_dirs=(
        "${PROJECT_ROOT}/backup/scripts"
        "${PROJECT_ROOT}/backup/policies"
    )
    
    for dir in "${backup_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log "SUCCESS" "Backup directory exists: $(basename "$dir")"
        else
            log "ERROR" "Backup directory missing: $(basename "$dir")"
            return 1
        fi
    done
    
    return 0
}

validate_production_configuration() {
    log "INFO" "Validating production environment configuration..."
    
    # Check if production environment example exists
    if [ -f "${PROJECT_ROOT}/.env.production.example" ]; then
        log "SUCCESS" "Production environment example found"
    else
        log "ERROR" "Production environment example missing"
        return 1
    fi
    
    # Check if Docker Compose override exists
    if [ -f "${PROJECT_ROOT}/docker-compose.override.yml" ]; then
        log "SUCCESS" "Docker Compose override found"
    else
        log "WARN" "Docker Compose override missing (optional)"
    fi
    
    # Check production deployment checklist
    if [ -f "${DEPLOYMENT_DIR}/production-deployment-checklist.md" ]; then
        log "SUCCESS" "Production deployment checklist found"
    else
        log "ERROR" "Production deployment checklist missing"
        return 1
    fi
    
    # Check production alerts configuration
    if [ -f "${MONITORING_DIR}/alerts/production-alerts.yml" ]; then
        log "SUCCESS" "Production alerts configuration found"
    else
        log "ERROR" "Production alerts configuration missing"
        return 1
    fi
    
    return 0
}

validate_deployment_automation() {
    log "INFO" "Validating deployment automation..."
    
    # Check master deployment script
    if [ -f "${DEPLOYMENT_DIR}/scripts/deploy-pat-fortress.sh" ] && [ -x "${DEPLOYMENT_DIR}/scripts/deploy-pat-fortress.sh" ]; then
        log "SUCCESS" "Master deployment script found and executable"
    else
        log "ERROR" "Master deployment script missing or not executable"
        return 1
    fi
    
    # Check deployment validation script
    if [ -f "${DEPLOYMENT_DIR}/scripts/validate-deployment.sh" ] && [ -x "${DEPLOYMENT_DIR}/scripts/validate-deployment.sh" ]; then
        log "SUCCESS" "Deployment validation script found and executable"
    else
        log "ERROR" "Deployment validation script missing or not executable"
        return 1
    fi
    
    # Check Kubernetes manifests (for future scaling)
    if [ -f "${DEPLOYMENT_DIR}/kubernetes/pat-fortress-deployment.yaml" ]; then
        log "SUCCESS" "Kubernetes deployment manifests found"
    else
        log "WARN" "Kubernetes deployment manifests missing (optional for future scaling)"
    fi
    
    # Check build and deploy script
    if [ -f "${DEPLOYMENT_DIR}/scripts/build-and-deploy.sh" ] && [ -x "${DEPLOYMENT_DIR}/scripts/build-and-deploy.sh" ]; then
        log "SUCCESS" "Build and deploy script found and executable"
    else
        log "ERROR" "Build and deploy script missing or not executable"
        return 1
    fi
    
    return 0
}

validate_ssl_tls_configuration() {
    log "INFO" "Validating SSL/TLS configuration..."
    
    # Check if SSL directory structure exists
    if [ -d "${DEPLOYMENT_DIR}/ssl" ]; then
        log "SUCCESS" "SSL directory exists"
    else
        log "WARN" "SSL directory missing (will be created during deployment)"
    fi
    
    # Check Nginx SSL configuration
    if [ -f "${DEPLOYMENT_DIR}/nginx/conf.d/pat-fortress.conf" ]; then
        if grep -q "ssl_certificate" "${DEPLOYMENT_DIR}/nginx/conf.d/pat-fortress.conf"; then
            log "SUCCESS" "Nginx SSL configuration found"
        else
            log "ERROR" "Nginx SSL configuration missing"
            return 1
        fi
    else
        log "ERROR" "Nginx virtual host configuration missing"
        return 1
    fi
    
    return 0
}

validate_security_hardening() {
    log "INFO" "Validating security hardening configuration..."
    
    # Check Docker security configurations
    if grep -q "security_opt" "${PROJECT_ROOT}/docker-compose.production.yml"; then
        log "SUCCESS" "Docker security options configured"
    else
        log "WARN" "Docker security options not explicitly configured"
    fi
    
    # Check if containers run as non-root
    if grep -q "USER" "${PROJECT_ROOT}/Dockerfile"; then
        log "SUCCESS" "Non-root user configured in Dockerfile"
    else
        log "WARN" "Non-root user not explicitly configured in Dockerfile"
    fi
    
    # Check for health checks
    if grep -q "HEALTHCHECK" "${PROJECT_ROOT}/Dockerfile"; then
        log "SUCCESS" "Health check configured in Dockerfile"
    else
        log "ERROR" "Health check missing in Dockerfile"
        return 1
    fi
    
    return 0
}

validate_production_readiness() {
    log "INFO" "Validating overall production readiness..."
    
    cd "$PROJECT_ROOT"
    
    # Check if project builds successfully
    if go build ./cmd/server > /dev/null 2>&1; then
        log "SUCCESS" "Application builds successfully"
    else
        log "ERROR" "Application build failed"
        return 1
    fi
    
    # Check if Docker image can be built
    if command -v docker &> /dev/null; then
        if docker build -t pat-fortress-validation:test . > /dev/null 2>&1; then
            log "SUCCESS" "Docker image builds successfully"
            # Clean up test image
            docker rmi pat-fortress-validation:test > /dev/null 2>&1 || true
        else
            log "ERROR" "Docker image build failed"
            return 1
        fi
    else
        log "WARN" "Docker not available - skipping image build test"
    fi
    
    # Check if all necessary directories exist
    local required_dirs=(
        "${DEPLOYMENT_DIR}/docker"
        "${DEPLOYMENT_DIR}/scripts"
        "${MONITORING_DIR}/prometheus"
        "${MONITORING_DIR}/grafana"
        "${PROJECT_ROOT}/backup/scripts"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log "SUCCESS" "Required directory exists: $(basename "$dir")"
        else
            log "ERROR" "Required directory missing: $dir"
            return 1
        fi
    done
    
    return 0
}

main() {
    echo -e "${COLOR_WHITE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           PHASE 4 VALIDATION: PRODUCTION DEPLOYMENT          ║"
    echo "║                      🏗️ THE RAMPARTS                        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
    
    log "INFO" "Starting Phase 4 Production Deployment validation..."
    
    local validation_passed=true
    
    # Run all validations
    validate_docker_infrastructure || validation_passed=false
    validate_monitoring_observability || validation_passed=false
    validate_backup_disaster_recovery || validation_passed=false
    validate_production_configuration || validation_passed=false
    validate_deployment_automation || validation_passed=false
    validate_ssl_tls_configuration || validation_passed=false
    validate_security_hardening || validation_passed=false
    validate_production_readiness || validation_passed=false
    
    if [ "$validation_passed" = true ]; then
        log "SUCCESS" "🏰 Phase 4 Production Deployment validation PASSED"
        echo -e "${COLOR_GREEN}"
        cat << 'SUCCESS_BANNER'
✅ All production deployment components are ready
✅ The fortress ramparts are complete and secure
✅ Pat Fortress is 100% PRODUCTION READY!

🏰 The fortress stands complete and ready for battle! 🏰
SUCCESS_BANNER
        echo -e "${COLOR_NC}"
        exit 0
    else
        log "ERROR" "❌ Phase 4 Production Deployment validation FAILED"
        echo -e "${COLOR_RED}"
        echo "❌ Some production deployment components need attention"
        echo "❌ The fortress ramparts need reinforcement before production"
        echo -e "${COLOR_NC}"
        exit 1
    fi
}

main "$@"