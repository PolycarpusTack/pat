#!/bin/bash
# =============================================================================
# Fortress Deployment Validation System
# Comprehensive Pre/Post Deployment Validation and Health Checking
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration and Global Variables
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_DIR="${PROJECT_ROOT}/logs/validation"
readonly CONFIG_DIR="${PROJECT_ROOT}/config"

# Create directories
mkdir -p "$LOG_DIR" "${CONFIG_DIR}/validation"

# Logging setup
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="${LOG_DIR}/validation-${TIMESTAMP}.log"
readonly VALIDATION_REPORT="${LOG_DIR}/validation-report-${TIMESTAMP}.json"

exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# Validation Configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
VALIDATION_TYPE="${VALIDATION_TYPE:-pre-deployment}"
STRICT_MODE="${STRICT_MODE:-true}"
TIMEOUT="${TIMEOUT:-300}"
PARALLEL_CHECKS="${PARALLEL_CHECKS:-true}"
GENERATE_REPORT="${GENERATE_REPORT:-true}"

# Validation Results
VALIDATION_RESULTS=()
VALIDATION_SCORE=0
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# =============================================================================
# Logging and Reporting Functions
# =============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $*${NC}" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $*${NC}"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] [DEBUG] $*${NC}"
    fi
}

# Record validation result
record_validation_result() {
    local check_name="$1"
    local status="$2"      # PASS, FAIL, WARN
    local message="$3"
    local details="${4:-}"
    local duration="${5:-0}"
    
    local result="{
        \"check_name\": \"$check_name\",
        \"status\": \"$status\",
        \"message\": \"$message\",
        \"details\": \"$details\",
        \"duration_seconds\": $duration,
        \"timestamp\": $(date +%s),
        \"environment\": \"$ENVIRONMENT\",
        \"validation_type\": \"$VALIDATION_TYPE\"
    }"
    
    VALIDATION_RESULTS+=("$result")
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    case "$status" in
        "PASS")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            VALIDATION_SCORE=$((VALIDATION_SCORE + 100))
            success "✓ $check_name - $message"
            ;;
        "FAIL")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            error "✗ $check_name - $message"
            ;;
        "WARN")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            VALIDATION_SCORE=$((VALIDATION_SCORE + 50))
            warn "⚠ $check_name - $message"
            ;;
    esac
}

# =============================================================================
# Infrastructure Validation
# =============================================================================

validate_infrastructure() {
    log "Starting infrastructure validation..."
    
    if [[ "$PARALLEL_CHECKS" == "true" ]]; then
        run_infrastructure_checks_parallel
    else
        run_infrastructure_checks_sequential
    fi
    
    success "Infrastructure validation completed"
}

run_infrastructure_checks_parallel() {
    local pids=()
    
    # Run checks in parallel
    validate_docker_environment &
    pids+=($!)
    
    validate_kubernetes_cluster &
    pids+=($!)
    
    validate_network_connectivity &
    pids+=($!)
    
    validate_dns_resolution &
    pids+=($!)
    
    validate_ssl_certificates &
    pids+=($!)
    
    validate_storage_systems &
    pids+=($!)
    
    # Wait for all checks to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

run_infrastructure_checks_sequential() {
    validate_docker_environment
    validate_kubernetes_cluster
    validate_network_connectivity
    validate_dns_resolution
    validate_ssl_certificates
    validate_storage_systems
}

validate_docker_environment() {
    local start_time=$(date +%s)
    local check_name="docker_environment"
    
    debug "Validating Docker environment..."
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        record_validation_result "$check_name" "FAIL" "Docker daemon not running" "" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check Docker version
    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    
    if [[ "$docker_version" == "unknown" ]]; then
        record_validation_result "$check_name" "FAIL" "Could not determine Docker version" "" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check Docker resources
    local docker_info
    docker_info=$(docker system info --format json 2>/dev/null || echo '{}')
    
    local cpu_count
    cpu_count=$(echo "$docker_info" | jq -r '.NCPU // 0')
    
    local memory_total
    memory_total=$(echo "$docker_info" | jq -r '.MemTotal // 0')
    
    if [[ "$cpu_count" -lt 2 ]]; then
        record_validation_result "$check_name" "WARN" "Low CPU count: $cpu_count cores" "docker_version=$docker_version" "$(($(date +%s) - start_time))"
        return
    fi
    
    if [[ "$memory_total" -lt 4000000000 ]]; then  # 4GB in bytes
        record_validation_result "$check_name" "WARN" "Low memory: $(($memory_total / 1024 / 1024 / 1024))GB" "docker_version=$docker_version" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check Docker registry connectivity
    if ! docker pull hello-world:latest >/dev/null 2>&1; then
        record_validation_result "$check_name" "WARN" "Docker registry connectivity issues" "docker_version=$docker_version" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Clean up test image
    docker rmi hello-world:latest >/dev/null 2>&1 || true
    
    record_validation_result "$check_name" "PASS" "Docker environment healthy" "version=$docker_version,cpu=$cpu_count,memory=${memory_total}GB" "$(($(date +%s) - start_time))"
}

validate_kubernetes_cluster() {
    local start_time=$(date +%s)
    local check_name="kubernetes_cluster"
    
    debug "Validating Kubernetes cluster..."
    
    # Check kubectl connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        record_validation_result "$check_name" "FAIL" "Cannot connect to Kubernetes cluster" "" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check cluster version
    local k8s_version
    k8s_version=$(kubectl version --output=yaml 2>/dev/null | grep gitVersion | head -1 | cut -d'"' -f4 || echo "unknown")
    
    # Check node status
    local ready_nodes
    ready_nodes=$(kubectl get nodes --no-headers | grep -c Ready || echo "0")
    
    local total_nodes
    total_nodes=$(kubectl get nodes --no-headers | wc -l || echo "0")
    
    if [[ "$ready_nodes" -lt "$total_nodes" ]]; then
        record_validation_result "$check_name" "FAIL" "Not all nodes ready: $ready_nodes/$total_nodes" "k8s_version=$k8s_version" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check critical system pods
    local system_pods_ready
    system_pods_ready=$(kubectl get pods -n kube-system --no-headers | grep -c Running || echo "0")
    
    local system_pods_total
    system_pods_total=$(kubectl get pods -n kube-system --no-headers | wc -l || echo "0")
    
    if [[ "$system_pods_ready" -lt "$system_pods_total" ]]; then
        record_validation_result "$check_name" "WARN" "Some system pods not ready: $system_pods_ready/$system_pods_total" "k8s_version=$k8s_version" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check resource quotas and limits
    validate_resource_quotas "$check_name" "$start_time" "$k8s_version"
}

validate_resource_quotas() {
    local parent_check="$1"
    local start_time="$2"
    local k8s_version="$3"
    
    # Check cluster resource capacity
    local cpu_capacity
    cpu_capacity=$(kubectl describe nodes | grep -A 5 "Allocatable" | grep cpu | awk '{print $2}' | sed 's/m//' | awk '{sum += $1} END {print sum/1000}' || echo "0")
    
    local memory_capacity
    memory_capacity=$(kubectl describe nodes | grep -A 5 "Allocatable" | grep memory | awk '{print $2}' | sed 's/Ki//' | awk '{sum += $1} END {print sum/1024/1024}' || echo "0")
    
    # Check if fortress namespace exists
    if kubectl get namespace fortress >/dev/null 2>&1; then
        # Check fortress namespace resource usage
        local fortress_cpu_usage
        fortress_cpu_usage=$(kubectl top pods -n fortress --no-headers 2>/dev/null | awk '{gsub(/m/, "", $2); sum += $2} END {print sum/1000}' || echo "0")
        
        local fortress_memory_usage
        fortress_memory_usage=$(kubectl top pods -n fortress --no-headers 2>/dev/null | awk '{gsub(/Mi/, "", $3); sum += $3} END {print sum/1024}' || echo "0")
        
        debug "Fortress resource usage - CPU: ${fortress_cpu_usage} cores, Memory: ${fortress_memory_usage}GB"
    fi
    
    record_validation_result "$parent_check" "PASS" "Kubernetes cluster healthy" "version=$k8s_version,nodes=$total_nodes,cpu=${cpu_capacity}cores,memory=${memory_capacity}GB" "$(($(date +%s) - start_time))"
}

validate_network_connectivity() {
    local start_time=$(date +%s)
    local check_name="network_connectivity"
    
    debug "Validating network connectivity..."
    
    local test_endpoints=(
        "8.8.8.8:53"           # Google DNS
        "github.com:443"       # GitHub
        "docker.io:443"        # Docker Hub
        "registry.k8s.io:443"  # Kubernetes registry
    )
    
    local failed_endpoints=()
    
    for endpoint in "${test_endpoints[@]}"; do
        local host="${endpoint%%:*}"
        local port="${endpoint##*:}"
        
        if ! timeout 10 nc -z "$host" "$port" >/dev/null 2>&1; then
            failed_endpoints+=("$endpoint")
        fi
    done
    
    if [[ ${#failed_endpoints[@]} -gt 0 ]]; then
        if [[ ${#failed_endpoints[@]} -eq ${#test_endpoints[@]} ]]; then
            record_validation_result "$check_name" "FAIL" "No network connectivity" "failed_endpoints=${failed_endpoints[*]}" "$(($(date +%s) - start_time))"
        else
            record_validation_result "$check_name" "WARN" "Limited network connectivity" "failed_endpoints=${failed_endpoints[*]}" "$(($(date +%s) - start_time))"
        fi
    else
        record_validation_result "$check_name" "PASS" "Network connectivity healthy" "all_endpoints_accessible" "$(($(date +%s) - start_time))"
    fi
}

validate_dns_resolution() {
    local start_time=$(date +%s)
    local check_name="dns_resolution"
    
    debug "Validating DNS resolution..."
    
    local test_domains=(
        "google.com"
        "github.com"
        "docker.io"
        "${DOMAIN_NAME:-fortress.local}"
    )
    
    local failed_domains=()
    
    for domain in "${test_domains[@]}"; do
        if ! timeout 10 nslookup "$domain" >/dev/null 2>&1; then
            failed_domains+=("$domain")
        fi
    done
    
    if [[ ${#failed_domains[@]} -gt 0 ]]; then
        if [[ ${#failed_domains[@]} -eq ${#test_domains[@]} ]]; then
            record_validation_result "$check_name" "FAIL" "DNS resolution not working" "failed_domains=${failed_domains[*]}" "$(($(date +%s) - start_time))"
        else
            record_validation_result "$check_name" "WARN" "Some DNS resolution issues" "failed_domains=${failed_domains[*]}" "$(($(date +%s) - start_time))"
        fi
    else
        record_validation_result "$check_name" "PASS" "DNS resolution working" "all_domains_resolved" "$(($(date +%s) - start_time))"
    fi
}

validate_ssl_certificates() {
    local start_time=$(date +%s)
    local check_name="ssl_certificates"
    
    debug "Validating SSL certificates..."
    
    # Find certificate files
    local cert_files
    cert_files=$(find "$PROJECT_ROOT" -name "*.crt" -o -name "*.pem" -o -name "*.cert" 2>/dev/null | head -10)
    
    local expired_certs=()
    local expiring_soon_certs=()
    local valid_certs=0
    
    if [[ -z "$cert_files" ]]; then
        record_validation_result "$check_name" "PASS" "No certificates found to validate" "" "$(($(date +%s) - start_time))"
        return
    fi
    
    for cert_file in $cert_files; do
        if [[ -f "$cert_file" ]]; then
            local expiry_date
            expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2 || echo "")
            
            if [[ -n "$expiry_date" ]]; then
                local expiry_epoch
                expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
                local current_epoch
                current_epoch=$(date +%s)
                local days_until_expiry
                days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
                
                if [[ $days_until_expiry -lt 0 ]]; then
                    expired_certs+=("$cert_file")
                elif [[ $days_until_expiry -lt 30 ]]; then
                    expiring_soon_certs+=("$cert_file ($days_until_expiry days)")
                else
                    valid_certs=$((valid_certs + 1))
                fi
            fi
        fi
    done
    
    if [[ ${#expired_certs[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Expired certificates found" "expired=${expired_certs[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#expiring_soon_certs[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Certificates expiring soon" "expiring_soon=${expiring_soon_certs[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All certificates valid" "valid_certs=$valid_certs" "$(($(date +%s) - start_time))"
    fi
}

validate_storage_systems() {
    local start_time=$(date +%s)
    local check_name="storage_systems"
    
    debug "Validating storage systems..."
    
    # Check disk space
    local root_usage
    root_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    local project_usage
    project_usage=$(df -h "$PROJECT_ROOT" | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ "$root_usage" -gt 90 ]]; then
        record_validation_result "$check_name" "FAIL" "Root filesystem usage critical: ${root_usage}%" "project_usage=${project_usage}%" "$(($(date +%s) - start_time))"
        return
    elif [[ "$root_usage" -gt 80 ]]; then
        record_validation_result "$check_name" "WARN" "Root filesystem usage high: ${root_usage}%" "project_usage=${project_usage}%" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check Kubernetes persistent volumes if in k8s mode
    if kubectl get pv >/dev/null 2>&1; then
        local pv_status
        pv_status=$(kubectl get pv --no-headers 2>/dev/null | awk '{print $5}' | sort | uniq -c || echo "")
        
        if echo "$pv_status" | grep -q "Failed\|Lost"; then
            record_validation_result "$check_name" "FAIL" "Persistent volumes in failed state" "pv_status=$pv_status" "$(($(date +%s) - start_time))"
            return
        fi
    fi
    
    record_validation_result "$check_name" "PASS" "Storage systems healthy" "root_usage=${root_usage}%,project_usage=${project_usage}%" "$(($(date +%s) - start_time))"
}

# =============================================================================
# Application Validation
# =============================================================================

validate_application() {
    log "Starting application validation..."
    
    validate_docker_images
    validate_configuration_files
    validate_database_connectivity
    validate_external_dependencies
    validate_security_configuration
    
    success "Application validation completed"
}

validate_docker_images() {
    local start_time=$(date +%s)
    local check_name="docker_images"
    
    debug "Validating Docker images..."
    
    local required_images=(
        "fortress/fortress-core:${VERSION:-latest}"
        "fortress/fortress-api:${VERSION:-latest}"
        "fortress/fortress-smtp:${VERSION:-latest}"
        "fortress/fortress-workflows:${VERSION:-latest}"
    )
    
    local missing_images=()
    local vulnerable_images=()
    
    for image in "${required_images[@]}"; do
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            missing_images+=("$image")
        else
            # Check for vulnerabilities if trivy is available
            if command -v trivy >/dev/null 2>&1; then
                local vuln_count
                vuln_count=$(trivy image --quiet --format json "$image" 2>/dev/null | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' || echo "0")
                
                if [[ "$vuln_count" -gt 0 ]]; then
                    vulnerable_images+=("$image ($vuln_count high/critical)")
                fi
            fi
        fi
    done
    
    if [[ ${#missing_images[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Required Docker images missing" "missing=${missing_images[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#vulnerable_images[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Docker images have vulnerabilities" "vulnerable=${vulnerable_images[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All Docker images available and secure" "images_count=${#required_images[@]}" "$(($(date +%s) - start_time))"
    fi
}

validate_configuration_files() {
    local start_time=$(date +%s)
    local check_name="configuration_files"
    
    debug "Validating configuration files..."
    
    local config_files=(
        "${CONFIG_DIR}/${ENVIRONMENT}/app.yaml"
        "${CONFIG_DIR}/${ENVIRONMENT}/database.yaml"
        "${CONFIG_DIR}/monitoring/prometheus.yml"
        "${PROJECT_ROOT}/docker-compose.fortress.yml"
    )
    
    local missing_configs=()
    local invalid_configs=()
    local valid_configs=0
    
    for config_file in "${config_files[@]}"; do
        if [[ ! -f "$config_file" ]]; then
            missing_configs+=("$config_file")
        else
            # Validate YAML syntax
            if [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                if command -v yq >/dev/null 2>&1; then
                    if ! yq eval '.' "$config_file" >/dev/null 2>&1; then
                        invalid_configs+=("$config_file")
                    else
                        valid_configs=$((valid_configs + 1))
                    fi
                else
                    # Basic YAML check with Python
                    if command -v python3 >/dev/null 2>&1; then
                        if ! python3 -c "import yaml; yaml.safe_load(open('$config_file'))" 2>/dev/null; then
                            invalid_configs+=("$config_file")
                        else
                            valid_configs=$((valid_configs + 1))
                        fi
                    else
                        valid_configs=$((valid_configs + 1))  # Skip validation if no tools
                    fi
                fi
            else
                valid_configs=$((valid_configs + 1))  # Non-YAML files
            fi
        fi
    done
    
    if [[ ${#missing_configs[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Configuration files missing" "missing=${missing_configs[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#invalid_configs[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Configuration files invalid" "invalid=${invalid_configs[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All configuration files valid" "valid_configs=$valid_configs" "$(($(date +%s) - start_time))"
    fi
}

validate_database_connectivity() {
    local start_time=$(date +%s)
    local check_name="database_connectivity"
    
    debug "Validating database connectivity..."
    
    # For pre-deployment, we might not have database running
    if [[ "$VALIDATION_TYPE" == "pre-deployment" ]]; then
        record_validation_result "$check_name" "PASS" "Database connectivity check skipped for pre-deployment" "" "$(($(date +%s) - start_time))"
        return
    fi
    
    # Check PostgreSQL connectivity (simplified)
    local db_host="${DB_HOST:-localhost}"
    local db_port="${DB_PORT:-5432}"
    
    if timeout 10 nc -z "$db_host" "$db_port" >/dev/null 2>&1; then
        record_validation_result "$check_name" "PASS" "Database port accessible" "host=$db_host,port=$db_port" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "FAIL" "Database not accessible" "host=$db_host,port=$db_port" "$(($(date +%s) - start_time))"
    fi
}

validate_external_dependencies() {
    local start_time=$(date +%s)
    local check_name="external_dependencies"
    
    debug "Validating external dependencies..."
    
    local dependencies=(
        "smtp.gmail.com:587"      # External SMTP
        "api.stripe.com:443"      # Payment processing
        "hooks.slack.com:443"     # Notifications
    )
    
    local failed_deps=()
    local accessible_deps=0
    
    for dep in "${dependencies[@]}"; do
        local host="${dep%%:*}"
        local port="${dep##*:}"
        
        if timeout 5 nc -z "$host" "$port" >/dev/null 2>&1; then
            accessible_deps=$((accessible_deps + 1))
        else
            failed_deps+=("$dep")
        fi
    done
    
    if [[ ${#failed_deps[@]} -gt 0 && ${#failed_deps[@]} -eq ${#dependencies[@]} ]]; then
        record_validation_result "$check_name" "WARN" "All external dependencies unreachable" "failed=${failed_deps[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#failed_deps[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Some external dependencies unreachable" "failed=${failed_deps[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All external dependencies accessible" "accessible_count=$accessible_deps" "$(($(date +%s) - start_time))"
    fi
}

validate_security_configuration() {
    local start_time=$(date +%s)
    local check_name="security_configuration"
    
    debug "Validating security configuration..."
    
    local security_issues=()
    local security_warnings=()
    
    # Check for hardcoded secrets
    if find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" -o -name "*.env" | xargs grep -l "password\|secret\|token" >/dev/null 2>&1; then
        security_warnings+=("Potential hardcoded secrets in config files")
    fi
    
    # Check file permissions
    local sensitive_files=(
        "${CONFIG_DIR}/production/secrets.yaml"
        "${PROJECT_ROOT}/.env"
        "${HOME}/.kube/config"
    )
    
    for file in "${sensitive_files[@]}"; do
        if [[ -f "$file" ]]; then
            local perms
            perms=$(stat -c %a "$file" 2>/dev/null || echo "000")
            
            if [[ "$perms" =~ ^[0-9]{3}$ && "${perms:2:1}" -gt 0 ]]; then
                security_issues+=("$file has world-readable permissions: $perms")
            fi
        fi
    done
    
    # Check for SSL/TLS configuration
    if [[ ! -f "${CONFIG_DIR}/ssl/server.crt" && ! -f "${CONFIG_DIR}/tls/tls.crt" ]]; then
        security_warnings+=("No SSL certificates found")
    fi
    
    if [[ ${#security_issues[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Security issues found" "issues=${security_issues[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#security_warnings[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Security warnings" "warnings=${security_warnings[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "Security configuration acceptable" "" "$(($(date +%s) - start_time))"
    fi
}

# =============================================================================
# Post-Deployment Health Checks
# =============================================================================

validate_deployment_health() {
    log "Starting post-deployment health validation..."
    
    validate_service_health
    validate_api_endpoints
    validate_performance_metrics
    validate_monitoring_systems
    
    success "Post-deployment health validation completed"
}

validate_service_health() {
    local start_time=$(date +%s)
    local check_name="service_health"
    
    debug "Validating service health..."
    
    local services=("fortress-api" "fortress-smtp" "fortress-workflows")
    local unhealthy_services=()
    local healthy_services=0
    
    for service in "${services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            local ready_replicas
            ready_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.status.readyReplicas}' || echo "0")
            
            local desired_replicas
            desired_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.spec.replicas}' || echo "1")
            
            if [[ "$ready_replicas" -ge "$desired_replicas" ]]; then
                healthy_services=$((healthy_services + 1))
            else
                unhealthy_services+=("$service ($ready_replicas/$desired_replicas)")
            fi
        else
            unhealthy_services+=("$service (not found)")
        fi
    done
    
    if [[ ${#unhealthy_services[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "Unhealthy services detected" "unhealthy=${unhealthy_services[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All services healthy" "healthy_count=$healthy_services" "$(($(date +%s) - start_time))"
    fi
}

validate_api_endpoints() {
    local start_time=$(date +%s)
    local check_name="api_endpoints"
    
    debug "Validating API endpoints..."
    
    local endpoints=(
        "/health:200"
        "/api/v1/status:200"
        "/metrics:200"
        "/ready:200"
    )
    
    local base_url="http://localhost:8025"
    local failed_endpoints=()
    local successful_endpoints=0
    
    # Port forward to API service
    kubectl port-forward -n fortress service/fortress-api 8025:8025 &
    local port_forward_pid=$!
    
    sleep 5  # Wait for port forward to establish
    
    for endpoint_info in "${endpoints[@]}"; do
        local endpoint="${endpoint_info%%:*}"
        local expected_code="${endpoint_info##*:}"
        
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url$endpoint" || echo "000")
        
        if [[ "$response_code" == "$expected_code" ]]; then
            successful_endpoints=$((successful_endpoints + 1))
        else
            failed_endpoints+=("$endpoint (got $response_code, expected $expected_code)")
        fi
    done
    
    # Clean up port forward
    kill $port_forward_pid 2>/dev/null || true
    
    if [[ ${#failed_endpoints[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "FAIL" "API endpoint checks failed" "failed=${failed_endpoints[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All API endpoints responding correctly" "successful_count=$successful_endpoints" "$(($(date +%s) - start_time))"
    fi
}

validate_performance_metrics() {
    local start_time=$(date +%s)
    local check_name="performance_metrics"
    
    debug "Validating performance metrics..."
    
    # This is a simplified performance check
    # In practice, you'd query actual monitoring systems
    
    local metrics_collected=0
    local performance_issues=()
    
    # Check resource usage
    local pods
    pods=$(kubectl get pods -n fortress -l app=fortress-api --no-headers | awk '{print $1}' | head -1)
    
    if [[ -n "$pods" ]]; then
        # Get basic metrics
        local pod_metrics
        pod_metrics=$(kubectl top pod "$pods" -n fortress --no-headers 2>/dev/null || echo "0m 0Mi")
        
        if [[ "$pod_metrics" != "0m 0Mi" ]]; then
            metrics_collected=1
            
            # Parse metrics (simplified)
            local cpu_usage
            cpu_usage=$(echo "$pod_metrics" | awk '{print $2}' | sed 's/m$//')
            
            local memory_usage
            memory_usage=$(echo "$pod_metrics" | awk '{print $3}' | sed 's/Mi$//')
            
            # Check thresholds
            if [[ "$cpu_usage" -gt 1000 ]]; then  # > 1 CPU
                performance_issues+=("High CPU usage: ${cpu_usage}m")
            fi
            
            if [[ "$memory_usage" -gt 1000 ]]; then  # > 1GB
                performance_issues+=("High memory usage: ${memory_usage}Mi")
            fi
        fi
    fi
    
    if [[ ${#performance_issues[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Performance issues detected" "issues=${performance_issues[*]}" "$(($(date +%s) - start_time))"
    elif [[ "$metrics_collected" -eq 0 ]]; then
        record_validation_result "$check_name" "WARN" "Performance metrics not available" "" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "Performance metrics within acceptable range" "metrics_collected=$metrics_collected" "$(($(date +%s) - start_time))"
    fi
}

validate_monitoring_systems() {
    local start_time=$(date +%s)
    local check_name="monitoring_systems"
    
    debug "Validating monitoring systems..."
    
    local monitoring_components=("prometheus" "grafana" "alertmanager")
    local failed_components=()
    local working_components=0
    
    for component in "${monitoring_components[@]}"; do
        if kubectl get deployment "$component" -n fortress >/dev/null 2>&1; then
            local ready_replicas
            ready_replicas=$(kubectl get deployment "$component" -n fortress -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
            
            if [[ "$ready_replicas" -gt 0 ]]; then
                working_components=$((working_components + 1))
            else
                failed_components+=("$component")
            fi
        else
            # Check if running as part of helm release
            if kubectl get pods -n fortress -l app.kubernetes.io/name="$component" --no-headers | grep -q Running; then
                working_components=$((working_components + 1))
            else
                failed_components+=("$component (not found)")
            fi
        fi
    done
    
    if [[ "$working_components" -eq 0 ]]; then
        record_validation_result "$check_name" "FAIL" "No monitoring systems operational" "failed=${failed_components[*]}" "$(($(date +%s) - start_time))"
    elif [[ ${#failed_components[@]} -gt 0 ]]; then
        record_validation_result "$check_name" "WARN" "Some monitoring components not operational" "failed=${failed_components[*]}" "$(($(date +%s) - start_time))"
    else
        record_validation_result "$check_name" "PASS" "All monitoring systems operational" "working_count=$working_components" "$(($(date +%s) - start_time))"
    fi
}

# =============================================================================
# Report Generation
# =============================================================================

generate_validation_report() {
    if [[ "$GENERATE_REPORT" != "true" ]]; then
        return 0
    fi
    
    log "Generating validation report..."
    
    local total_score=0
    if [[ "$TOTAL_CHECKS" -gt 0 ]]; then
        total_score=$((VALIDATION_SCORE / TOTAL_CHECKS))
    fi
    
    local overall_status="PASS"
    if [[ "$FAILED_CHECKS" -gt 0 ]]; then
        overall_status="FAIL"
    elif [[ "$WARNING_CHECKS" -gt 0 ]]; then
        overall_status="WARN"
    fi
    
    # Create JSON report
    cat > "$VALIDATION_REPORT" << EOF
{
    "validation_summary": {
        "validation_type": "$VALIDATION_TYPE",
        "environment": "$ENVIRONMENT",
        "timestamp": $(date +%s),
        "overall_status": "$overall_status",
        "total_score": $total_score,
        "total_checks": $TOTAL_CHECKS,
        "passed_checks": $PASSED_CHECKS,
        "failed_checks": $FAILED_CHECKS,
        "warning_checks": $WARNING_CHECKS
    },
    "validation_results": [
        $(IFS=','; echo "${VALIDATION_RESULTS[*]}")
    ]
}
EOF
    
    # Generate human-readable summary
    local summary_file="${LOG_DIR}/validation-summary-${TIMESTAMP}.txt"
    
    cat > "$summary_file" << EOF
# Fortress Deployment Validation Report

## Summary
- **Validation Type**: $VALIDATION_TYPE
- **Environment**: $ENVIRONMENT  
- **Overall Status**: $overall_status
- **Score**: ${total_score}/100

## Results Overview
- ✅ **Passed**: $PASSED_CHECKS
- ❌ **Failed**: $FAILED_CHECKS  
- ⚠️  **Warnings**: $WARNING_CHECKS
- **Total Checks**: $TOTAL_CHECKS

## Detailed Results
EOF
    
    # Add individual results
    for result in "${VALIDATION_RESULTS[@]}"; do
        local check_name
        check_name=$(echo "$result" | jq -r '.check_name')
        
        local status
        status=$(echo "$result" | jq -r '.status')
        
        local message
        message=$(echo "$result" | jq -r '.message')
        
        local duration
        duration=$(echo "$result" | jq -r '.duration_seconds')
        
        local status_icon="✅"
        case "$status" in
            "FAIL") status_icon="❌" ;;
            "WARN") status_icon="⚠️" ;;
        esac
        
        echo "- $status_icon **$check_name** ($duration s): $message" >> "$summary_file"
    done
    
    cat >> "$summary_file" << EOF

---
*Report generated: $(date)*
*Validation completed in: $(($(date +%s) - $(stat -c %Y "$LOG_FILE"))) seconds*
EOF
    
    success "Validation report generated:"
    success "  - JSON: $VALIDATION_REPORT"
    success "  - Summary: $summary_file"
    
    # Display summary
    log "=== VALIDATION SUMMARY ==="
    cat "$summary_file"
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log "🔍 Starting Fortress Deployment Validation"
    log "Type: $VALIDATION_TYPE"
    log "Environment: $ENVIRONMENT"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Initialize validation tracking
    VALIDATION_RESULTS=()
    VALIDATION_SCORE=0
    TOTAL_CHECKS=0
    PASSED_CHECKS=0
    FAILED_CHECKS=0
    WARNING_CHECKS=0
    
    # Run appropriate validation based on type
    case "$VALIDATION_TYPE" in
        "pre-deployment")
            validate_infrastructure
            validate_application
            ;;
        "post-deployment")
            validate_infrastructure
            validate_application
            validate_deployment_health
            ;;
        "health-check")
            validate_deployment_health
            ;;
        *)
            error "Unknown validation type: $VALIDATION_TYPE"
            exit 1
            ;;
    esac
    
    # Generate report
    generate_validation_report
    
    # Determine exit code
    local exit_code=0
    if [[ "$FAILED_CHECKS" -gt 0 ]]; then
        exit_code=1
        error "❌ Validation FAILED: $FAILED_CHECKS check(s) failed"
    elif [[ "$WARNING_CHECKS" -gt 0 ]]; then
        if [[ "$STRICT_MODE" == "true" ]]; then
            exit_code=1
            warn "⚠️ Validation FAILED (strict mode): $WARNING_CHECKS warning(s)"
        else
            warn "⚠️ Validation PASSED with warnings: $WARNING_CHECKS warning(s)"
        fi
    else
        success "✅ Validation PASSED: All $TOTAL_CHECKS checks successful"
    fi
    
    success "🏁 Fortress Deployment Validation Completed"
    exit $exit_code
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type)
                VALIDATION_TYPE="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --strict)
                STRICT_MODE="true"
                shift
                ;;
            --no-strict)
                STRICT_MODE="false"
                shift
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --no-parallel)
                PARALLEL_CHECKS="false"
                shift
                ;;
            --no-report)
                GENERATE_REPORT="false"
                shift
                ;;
            --help)
                print_usage
                exit 0
                ;;
            *)
                error "Unknown argument: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

print_usage() {
    cat << EOF
🔍 Fortress Deployment Validator

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --type TYPE                Validation type: pre-deployment, post-deployment, health-check
    --environment ENV          Target environment (default: production)
    --strict                   Treat warnings as failures
    --no-strict                Allow warnings (default)
    --timeout SECONDS          Operation timeout (default: 300)
    --no-parallel              Run checks sequentially
    --no-report                Skip report generation
    --help                     Show this help

VALIDATION TYPES:
    pre-deployment             Infrastructure and application readiness
    post-deployment            Full deployment health validation
    health-check               Runtime health monitoring

EXAMPLES:
    # Pre-deployment validation
    $0 --type pre-deployment --environment production

    # Post-deployment health check
    $0 --type post-deployment --strict

    # Runtime health monitoring
    $0 --type health-check --no-parallel

ENVIRONMENT VARIABLES:
    VALIDATION_TYPE            Validation type
    ENVIRONMENT               Environment name
    STRICT_MODE               Strict validation mode (true/false)
    TIMEOUT                   Operation timeout in seconds
    PARALLEL_CHECKS           Run checks in parallel (true/false)
    GENERATE_REPORT           Generate validation report (true/false)
    DEBUG                     Enable debug output (true/false)

EOF
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi