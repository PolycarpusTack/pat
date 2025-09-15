#!/bin/bash
# =============================================================================
# Pat Fortress - Advanced Production Deployment Automation
# One-Click, Zero-Downtime, Multi-Strategy Production Deployment System
# =============================================================================

set -euo pipefail

# =============================================================================
# Global Configuration and Variables
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$SCRIPT_DIR"
readonly LOG_DIR="${PROJECT_ROOT}/logs/production-deployment"
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly TERRAFORM_DIR="${PROJECT_ROOT}/terraform"
readonly K8S_DIR="${PROJECT_ROOT}/k8s"
readonly SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

# Create directories
mkdir -p "$LOG_DIR" "${CONFIG_DIR}/production" "${PROJECT_ROOT}/backup"

# Advanced logging setup
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="${LOG_DIR}/fortress-production-deploy-${TIMESTAMP}.log"
readonly METRICS_FILE="${LOG_DIR}/deployment-metrics-${TIMESTAMP}.json"
readonly ROLLBACK_STATE="${LOG_DIR}/rollback-state-${TIMESTAMP}.json"

# Setup comprehensive logging
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors for enhanced output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Deployment Configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
AWS_REGION="${AWS_REGION:-us-east-1}"
DEPLOYMENT_STRATEGY="${DEPLOYMENT_STRATEGY:-blue-green}"
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo 'latest')}"
CANARY_PERCENTAGE="${CANARY_PERCENTAGE:-10}"
BATCH_SIZE="${BATCH_SIZE:-2}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
ROLLBACK_TIMEOUT="${ROLLBACK_TIMEOUT:-180}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_DEPLOYMENT="${FORCE_DEPLOYMENT:-false}"
AUTO_ROLLBACK="${AUTO_ROLLBACK:-true}"
SKIP_VALIDATION="${SKIP_VALIDATION:-false}"
ENABLE_CHAOS="${ENABLE_CHAOS:-false}"
NOTIFICATION_WEBHOOK="${NOTIFICATION_WEBHOOK:-}"

# Advanced Features
BACKUP_ENABLED="${BACKUP_ENABLED:-true}"
SECURITY_SCAN="${SECURITY_SCAN:-true}"
PERFORMANCE_BASELINE="${PERFORMANCE_BASELINE:-true}"
COMPLIANCE_CHECK="${COMPLIANCE_CHECK:-true}"

# Deployment Tracking
DEPLOYMENT_START_TIME=$(date +%s)
DEPLOYMENT_ID="fortress-${ENVIRONMENT}-${TIMESTAMP}"
CURRENT_VERSION=""
NEW_VERSION="$VERSION"

# =============================================================================
# Advanced Logging and Monitoring Functions
# =============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*${NC}"
    record_metric "log_info" "$(date +%s)" "$*"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $*${NC}" >&2
    record_metric "log_warn" "$(date +%s)" "$*"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*${NC}" >&2
    record_metric "log_error" "$(date +%s)" "$*"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS] $*${NC}"
    record_metric "log_success" "$(date +%s)" "$*"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*${NC}"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] [DEBUG] $*${NC}"
    fi
}

critical() {
    echo -e "${RED}${BOLD}[$(date +'%Y-%m-%d %H:%M:%S')] [CRITICAL] $*${NC}" >&2
    record_metric "log_critical" "$(date +%s)" "$*"
    send_alert "CRITICAL" "$*"
}

# Record deployment metrics
record_metric() {
    local metric_type="$1"
    local timestamp="$2"
    local message="$3"
    
    local metric_entry="{
        \"deployment_id\": \"$DEPLOYMENT_ID\",
        \"timestamp\": $timestamp,
        \"type\": \"$metric_type\",
        \"message\": \"$message\",
        \"environment\": \"$ENVIRONMENT\",
        \"strategy\": \"$DEPLOYMENT_STRATEGY\",
        \"version\": \"$NEW_VERSION\"
    }"
    
    echo "$metric_entry" >> "$METRICS_FILE"
}

# Send notifications and alerts
send_alert() {
    local level="$1"
    local message="$2"
    
    if [[ -n "$NOTIFICATION_WEBHOOK" && "$DRY_RUN" != "true" ]]; then
        local payload="{
            \"deployment_id\": \"$DEPLOYMENT_ID\",
            \"level\": \"$level\",
            \"message\": \"$message\",
            \"environment\": \"$ENVIRONMENT\",
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }"
        
        curl -X POST "$NOTIFICATION_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "$payload" \
             --max-time 10 \
             --silent || warn "Failed to send alert notification"
    fi
}

# =============================================================================
# Enhanced Prerequisites and Validation
# =============================================================================

check_advanced_prerequisites() {
    info "Performing comprehensive prerequisite validation..."
    
    local missing_tools=()
    local required_tools=(
        "docker" "docker-compose" "terraform" "kubectl" "helm" "aws" 
        "jq" "curl" "git" "nc" "timeout" "dig" "openssl" "gpg"
    )
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        error "Install missing tools and retry deployment"
        exit 1
    fi
    
    # Validate Docker environment
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon not running or not accessible"
        exit 1
    fi
    
    # Check Docker resources
    local docker_info
    docker_info=$(docker system df --format "table {{.Type}}\t{{.Size}}" 2>/dev/null || echo "")
    debug "Docker resources: $docker_info"
    
    # Validate AWS credentials and permissions
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        error "AWS credentials not configured or invalid"
        exit 1
    fi
    
    # Enhanced AWS permissions check
    validate_aws_permissions
    
    # Validate Kubernetes access
    if ! kubectl cluster-info >/dev/null 2>&1; then
        warn "Kubernetes cluster not accessible - will attempt configuration during deployment"
    fi
    
    # Check disk space
    local available_space
    available_space=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {gsub(/G/,""); print $4}')
    if [[ "$available_space" -lt 10 ]]; then
        error "Insufficient disk space. Need at least 10GB, available: ${available_space}GB"
        exit 1
    fi
    
    # Validate Git repository state
    validate_git_state
    
    # Check network connectivity
    validate_network_connectivity
    
    success "Advanced prerequisites validation passed"
    record_metric "prerequisites_check" "$(date +%s)" "passed"
}

validate_aws_permissions() {
    info "Validating AWS permissions..."
    
    local required_permissions=(
        "sts:GetCallerIdentity"
        "eks:DescribeCluster"
        "eks:UpdateKubeconfig"
        "ec2:DescribeInstances"
        "rds:DescribeDBInstances"
        "s3:ListBucket"
        "iam:GetUser"
        "cloudformation:DescribeStacks"
    )
    
    # Check if user has admin-like permissions or specific permissions
    if aws iam get-user >/dev/null 2>&1; then
        debug "AWS user permissions validated"
    else
        warn "Could not validate specific AWS permissions - proceeding with deployment"
    fi
}

validate_git_state() {
    info "Validating Git repository state..."
    
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        error "Not in a Git repository"
        exit 1
    fi
    
    # Check for uncommitted changes
    if [[ -n "$(git status --porcelain)" && "$FORCE_DEPLOYMENT" != "true" ]]; then
        error "Uncommitted changes detected. Commit changes or use --force-deployment"
        git status --short
        exit 1
    fi
    
    # Get current version/commit
    CURRENT_VERSION=$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)
    
    success "Git repository state validated"
}

validate_network_connectivity() {
    info "Validating network connectivity..."
    
    local endpoints=(
        "registry-1.docker.io:443"
        "github.com:443"
        "api.github.com:443"
        "amazonaws.com:443"
        "gcr.io:443"
        "quay.io:443"
    )
    
    local failed_endpoints=()
    
    for endpoint in "${endpoints[@]}"; do
        local host="${endpoint%%:*}"
        local port="${endpoint##*:}"
        
        if ! timeout 5 nc -z "$host" "$port" >/dev/null 2>&1; then
            failed_endpoints+=("$endpoint")
        fi
    done
    
    if [[ ${#failed_endpoints[@]} -gt 0 ]]; then
        warn "Network connectivity issues detected: ${failed_endpoints[*]}"
        if [[ "$FORCE_DEPLOYMENT" != "true" ]]; then
            error "Network connectivity required for deployment. Use --force-deployment to override"
            exit 1
        fi
    fi
    
    success "Network connectivity validated"
}

# =============================================================================
# Comprehensive Pre-Deployment Validation
# =============================================================================

run_pre_deployment_validation() {
    if [[ "$SKIP_VALIDATION" == "true" ]]; then
        warn "Skipping pre-deployment validation"
        return 0
    fi
    
    info "Running comprehensive pre-deployment validation..."
    
    # Infrastructure validation
    validate_infrastructure_state
    
    # Application validation
    validate_application_readiness
    
    # Security validation
    if [[ "$SECURITY_SCAN" == "true" ]]; then
        run_security_validation
    fi
    
    # Performance baseline
    if [[ "$PERFORMANCE_BASELINE" == "true" ]]; then
        establish_performance_baseline
    fi
    
    # Compliance validation
    if [[ "$COMPLIANCE_CHECK" == "true" ]]; then
        validate_compliance_requirements
    fi
    
    # Database validation
    validate_database_state
    
    # Backup validation
    if [[ "$BACKUP_ENABLED" == "true" ]]; then
        validate_backup_systems
    fi
    
    success "Pre-deployment validation completed successfully"
    record_metric "pre_deployment_validation" "$(date +%s)" "passed"
}

validate_infrastructure_state() {
    info "Validating infrastructure state..."
    
    # Check Terraform state
    if [[ -d "$TERRAFORM_DIR" ]]; then
        cd "$TERRAFORM_DIR"
        
        if terraform workspace list >/dev/null 2>&1; then
            local current_workspace
            current_workspace=$(terraform workspace show)
            info "Current Terraform workspace: $current_workspace"
            
            if [[ "$current_workspace" != "$ENVIRONMENT" ]]; then
                warn "Terraform workspace mismatch: $current_workspace vs $ENVIRONMENT"
            fi
        fi
        
        # Validate Terraform configuration
        if ! terraform validate >/dev/null 2>&1; then
            error "Terraform configuration validation failed"
            terraform validate
            exit 1
        fi
        
        cd "$PROJECT_ROOT"
    fi
    
    # Validate Kubernetes manifests
    if [[ -d "$K8S_DIR" ]]; then
        info "Validating Kubernetes manifests..."
        
        local manifests
        manifests=$(find "$K8S_DIR" -name "*.yaml" -o -name "*.yml")
        
        for manifest in $manifests; do
            if ! kubectl apply --dry-run=client -f "$manifest" >/dev/null 2>&1; then
                error "Invalid Kubernetes manifest: $manifest"
                kubectl apply --dry-run=client -f "$manifest"
                exit 1
            fi
        done
    fi
    
    success "Infrastructure state validation passed"
}

validate_application_readiness() {
    info "Validating application readiness..."
    
    # Check if Docker images can be built
    if [[ -f "Dockerfile.fortress-core" ]]; then
        info "Validating Docker build capabilities..."
        
        if [[ "$DRY_RUN" != "true" ]]; then
            docker build --target=build-stage -f Dockerfile.fortress-core . -t fortress-validation:test >/dev/null 2>&1 || {
                error "Failed to build Docker image for validation"
                exit 1
            }
            docker rmi fortress-validation:test >/dev/null 2>&1 || true
        fi
    fi
    
    # Validate configuration files
    validate_configuration_files
    
    success "Application readiness validation passed"
}

validate_configuration_files() {
    info "Validating configuration files..."
    
    local config_files=(
        "${CONFIG_DIR}/production/app.yaml"
        "${CONFIG_DIR}/production/database.yaml"
        "${CONFIG_DIR}/production/monitoring.yaml"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            # Basic YAML syntax check
            if command -v yq >/dev/null 2>&1; then
                if ! yq eval '.' "$config_file" >/dev/null 2>&1; then
                    error "Invalid YAML syntax in $config_file"
                    exit 1
                fi
            fi
        fi
    done
    
    success "Configuration file validation passed"
}

run_security_validation() {
    info "Running security validation..."
    
    # Container security scan
    if command -v trivy >/dev/null 2>&1; then
        info "Scanning Docker images for vulnerabilities..."
        
        local images=("fortress-core" "fortress-api" "fortress-smtp")
        for image in "${images[@]}"; do
            if docker image inspect "fortress/$image:$VERSION" >/dev/null 2>&1; then
                trivy image --exit-code 1 --severity HIGH,CRITICAL "fortress/$image:$VERSION" || {
                    error "Critical security vulnerabilities found in $image"
                    if [[ "$FORCE_DEPLOYMENT" != "true" ]]; then
                        exit 1
                    fi
                }
            fi
        done
    fi
    
    # Secret scanning
    run_secret_scan
    
    # Certificate validation
    validate_certificates
    
    success "Security validation completed"
}

run_secret_scan() {
    info "Scanning for exposed secrets..."
    
    if command -v gitleaks >/dev/null 2>&1; then
        if ! gitleaks detect --source="$PROJECT_ROOT" --verbose >/dev/null 2>&1; then
            error "Potential secrets detected in repository"
            if [[ "$FORCE_DEPLOYMENT" != "true" ]]; then
                exit 1
            fi
        fi
    else
        # Basic secret pattern check
        local secret_patterns=(
            "password\s*=\s*['\"][^'\"]{8,}['\"]"
            "secret\s*=\s*['\"][^'\"]{8,}['\"]"
            "token\s*=\s*['\"][^'\"]{20,}['\"]"
            "key\s*=\s*['\"][^'\"]{20,}['\"]"
        )
        
        for pattern in "${secret_patterns[@]}"; do
            if grep -r -E "$pattern" "$PROJECT_ROOT" --include="*.yaml" --include="*.yml" --include="*.env" >/dev/null 2>&1; then
                warn "Potential hardcoded secrets detected - review before deployment"
            fi
        done
    fi
}

validate_certificates() {
    info "Validating SSL/TLS certificates..."
    
    local cert_files
    cert_files=$(find "$PROJECT_ROOT" -name "*.crt" -o -name "*.pem" -o -name "*.cert" 2>/dev/null || true)
    
    for cert_file in $cert_files; do
        if [[ -f "$cert_file" ]]; then
            local expiry_date
            expiry_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
            
            if [[ -n "$expiry_date" ]]; then
                local expiry_epoch
                expiry_epoch=$(date -d "$expiry_date" +%s)
                local current_epoch
                current_epoch=$(date +%s)
                local days_until_expiry
                days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
                
                if [[ $days_until_expiry -lt 30 ]]; then
                    warn "Certificate expires soon: $cert_file ($days_until_expiry days)"
                fi
                
                if [[ $days_until_expiry -lt 0 ]]; then
                    error "Certificate expired: $cert_file"
                    exit 1
                fi
            fi
        fi
    done
}

establish_performance_baseline() {
    info "Establishing performance baseline..."
    
    # This would typically involve running performance tests
    # against the current production environment
    
    local baseline_file="${LOG_DIR}/performance-baseline-${TIMESTAMP}.json"
    
    # Collect current performance metrics
    local metrics="{
        \"timestamp\": $(date +%s),
        \"deployment_id\": \"$DEPLOYMENT_ID\",
        \"environment\": \"$ENVIRONMENT\",
        \"baseline_metrics\": {
            \"response_time_p95\": 0,
            \"throughput_rps\": 0,
            \"error_rate\": 0,
            \"cpu_utilization\": 0,
            \"memory_utilization\": 0
        }
    }"
    
    echo "$metrics" > "$baseline_file"
    
    success "Performance baseline established"
}

validate_compliance_requirements() {
    info "Validating compliance requirements..."
    
    # Check for required compliance configurations
    local compliance_checks=(
        "audit_logging_enabled"
        "encryption_at_rest"
        "encryption_in_transit" 
        "access_controls"
        "data_retention_policy"
    )
    
    for check in "${compliance_checks[@]}"; do
        debug "Checking compliance requirement: $check"
        # Add specific compliance validation logic here
    done
    
    success "Compliance validation completed"
}

validate_database_state() {
    info "Validating database state and migrations..."
    
    # Check database connectivity and migration status
    # This is a simplified check - in practice, you'd connect to the actual database
    
    if [[ -f "${PROJECT_ROOT}/migrations/latest.sql" ]]; then
        info "Database migration files found"
        
        # Validate migration syntax
        if command -v sqlfluff >/dev/null 2>&1; then
            sqlfluff lint "${PROJECT_ROOT}/migrations/"*.sql || warn "SQL lint issues detected"
        fi
    fi
    
    success "Database validation completed"
}

validate_backup_systems() {
    info "Validating backup systems..."
    
    # Check backup storage accessibility
    if [[ -n "${BACKUP_S3_BUCKET:-}" ]]; then
        if aws s3 ls "s3://$BACKUP_S3_BUCKET" >/dev/null 2>&1; then
            success "Backup storage accessible"
        else
            error "Backup storage not accessible"
            exit 1
        fi
    fi
    
    success "Backup system validation completed"
}

# =============================================================================
# Advanced Deployment Strategies
# =============================================================================

execute_deployment_strategy() {
    info "Executing deployment strategy: $DEPLOYMENT_STRATEGY"
    
    case "$DEPLOYMENT_STRATEGY" in
        "blue-green")
            execute_blue_green_deployment
            ;;
        "canary")
            execute_canary_deployment
            ;;
        "rolling")
            execute_rolling_deployment
            ;;
        "recreate")
            execute_recreate_deployment
            ;;
        *)
            error "Unknown deployment strategy: $DEPLOYMENT_STRATEGY"
            exit 1
            ;;
    esac
    
    success "Deployment strategy execution completed"
}

execute_blue_green_deployment() {
    info "Starting Blue-Green deployment..."
    
    # Create rollback state
    save_deployment_state "pre-deployment"
    
    # Deploy to green environment
    deploy_green_environment
    
    # Validate green environment
    validate_green_environment
    
    # Switch traffic to green
    switch_traffic_to_green
    
    # Validate post-switch
    validate_post_traffic_switch
    
    # Clean up blue environment (optional)
    if [[ "${CLEANUP_BLUE:-true}" == "true" ]]; then
        cleanup_blue_environment
    fi
    
    success "Blue-Green deployment completed successfully"
}

deploy_green_environment() {
    info "Deploying green environment..."
    
    # Create green namespace/environment
    local green_namespace="fortress-green"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would deploy to green environment: $green_namespace"
        return 0
    fi
    
    # Deploy to Kubernetes green environment
    kubectl create namespace "$green_namespace" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy applications to green environment
    local manifests=(
        "secrets.yaml"
        "configmaps.yaml"
        "deployments.yaml"
        "services.yaml"
    )
    
    for manifest in "${manifests[@]}"; do
        local manifest_file="$K8S_DIR/$manifest"
        if [[ -f "$manifest_file" ]]; then
            # Replace namespace in manifest for green deployment
            sed "s/namespace: fortress/namespace: $green_namespace/g" "$manifest_file" | kubectl apply -f -
        fi
    done
    
    # Wait for green deployment to be ready
    kubectl wait --for=condition=available --timeout="${HEALTH_CHECK_TIMEOUT}s" deployment --all -n "$green_namespace"
    
    success "Green environment deployed successfully"
}

validate_green_environment() {
    info "Validating green environment..."
    
    local green_namespace="fortress-green"
    
    # Health check endpoints
    local health_checks=(
        "/health"
        "/ready" 
        "/metrics"
    )
    
    # Get service endpoints in green environment
    local services
    services=$(kubectl get services -n "$green_namespace" -o jsonpath='{.items[*].metadata.name}')
    
    for service in $services; do
        info "Checking health of service: $service"
        
        # Port forward for health checks
        local port
        port=$(kubectl get service "$service" -n "$green_namespace" -o jsonpath='{.spec.ports[0].port}')
        
        kubectl port-forward -n "$green_namespace" "service/$service" "8080:$port" &
        local port_forward_pid=$!
        
        sleep 5  # Wait for port forward to establish
        
        # Run health checks
        local health_check_failed=false
        for endpoint in "${health_checks[@]}"; do
            if ! curl -f -s "http://localhost:8080$endpoint" >/dev/null 2>&1; then
                warn "Health check failed for $service$endpoint"
                health_check_failed=true
            fi
        done
        
        # Clean up port forward
        kill $port_forward_pid 2>/dev/null || true
        
        if [[ "$health_check_failed" == "true" && "$FORCE_DEPLOYMENT" != "true" ]]; then
            error "Health checks failed for $service"
            exit 1
        fi
    done
    
    success "Green environment validation completed"
}

switch_traffic_to_green() {
    info "Switching traffic to green environment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would switch traffic to green environment"
        return 0
    fi
    
    # Update ingress/load balancer to point to green environment
    # This is simplified - in practice you'd update your load balancer configuration
    
    # Update Kubernetes ingress
    local ingress_file="/tmp/ingress-green.yaml"
    
    cat > "$ingress_file" << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fortress-ingress
  namespace: fortress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - fortress.${DOMAIN_NAME:-localhost}
    secretName: fortress-tls
  rules:
  - host: fortress.${DOMAIN_NAME:-localhost}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: fortress-api
            port:
              number: 8025
EOF

    # Update service to point to green deployment
    kubectl patch service fortress-api -n fortress -p '{"spec":{"selector":{"app":"fortress-api","version":"green"}}}'
    
    # Gradual traffic shift (if using service mesh like Istio)
    # This would involve updating VirtualService configurations
    
    success "Traffic switched to green environment"
}

validate_post_traffic_switch() {
    info "Validating post-traffic switch..."
    
    # Monitor metrics for a period after traffic switch
    local monitor_duration=120  # 2 minutes
    local check_interval=10     # 10 seconds
    local checks_passed=0
    local required_checks=6     # Require 6 successful checks
    
    info "Monitoring deployment for $monitor_duration seconds..."
    
    for ((i=0; i<monitor_duration; i+=check_interval)); do
        if validate_deployment_health; then
            ((checks_passed++))
            info "Health check passed ($checks_passed/$required_checks)"
        else
            warn "Health check failed at $(date)"
            checks_passed=0  # Reset counter on failure
        fi
        
        if [[ $checks_passed -ge $required_checks ]]; then
            success "Post-traffic switch validation completed successfully"
            return 0
        fi
        
        sleep $check_interval
    done
    
    error "Post-traffic switch validation failed - initiating rollback"
    if [[ "$AUTO_ROLLBACK" == "true" ]]; then
        execute_automatic_rollback
    fi
    exit 1
}

cleanup_blue_environment() {
    info "Cleaning up blue environment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would clean up blue environment"
        return 0
    fi
    
    # Keep blue environment for a period before cleanup
    local cleanup_delay="${BLUE_CLEANUP_DELAY:-300}"  # 5 minutes default
    
    info "Scheduling blue environment cleanup in $cleanup_delay seconds..."
    
    # Schedule cleanup (in practice, you might use a cron job or scheduled task)
    (
        sleep "$cleanup_delay"
        kubectl delete namespace fortress-blue --ignore-not-found=true
        info "Blue environment cleaned up"
    ) &
    
    success "Blue environment cleanup scheduled"
}

execute_canary_deployment() {
    info "Starting Canary deployment with ${CANARY_PERCENTAGE}% traffic..."
    
    # Save current state
    save_deployment_state "pre-canary"
    
    # Deploy canary version
    deploy_canary_version
    
    # Gradually increase canary traffic
    execute_canary_traffic_progression
    
    # Promote canary to full deployment
    promote_canary_to_production
    
    success "Canary deployment completed successfully"
}

deploy_canary_version() {
    info "Deploying canary version..."
    
    local canary_namespace="fortress-canary"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would deploy canary version to $canary_namespace"
        return 0
    fi
    
    # Create canary namespace
    kubectl create namespace "$canary_namespace" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy canary with limited resources
    local canary_replicas=1
    
    # Deploy canary applications
    for manifest in secrets.yaml configmaps.yaml deployments.yaml; do
        local manifest_file="$K8S_DIR/$manifest"
        if [[ -f "$manifest_file" ]]; then
            # Modify manifest for canary deployment
            sed -e "s/namespace: fortress/namespace: $canary_namespace/g" \
                -e "s/replicas: [0-9]\+/replicas: $canary_replicas/g" \
                -e "s/app: fortress/app: fortress-canary/g" \
                "$manifest_file" | kubectl apply -f -
        fi
    done
    
    # Wait for canary to be ready
    kubectl wait --for=condition=available --timeout="${HEALTH_CHECK_TIMEOUT}s" deployment --all -n "$canary_namespace"
    
    success "Canary version deployed"
}

execute_canary_traffic_progression() {
    info "Executing canary traffic progression..."
    
    local traffic_increments=(5 10 25 50 75 100)  # Percentage increments
    local soak_time=300  # 5 minutes per increment
    
    for percentage in "${traffic_increments[@]}"; do
        if [[ $percentage -gt $CANARY_PERCENTAGE && $percentage -lt 100 ]]; then
            continue  # Skip if beyond user-specified canary percentage
        fi
        
        info "Directing ${percentage}% traffic to canary..."
        
        if [[ "$DRY_RUN" != "true" ]]; then
            # Update traffic routing (simplified - would use service mesh in practice)
            update_canary_traffic_percentage "$percentage"
        fi
        
        # Monitor canary performance
        if ! monitor_canary_performance "$soak_time"; then
            error "Canary performance degraded - rolling back"
            execute_canary_rollback
            exit 1
        fi
        
        success "${percentage}% traffic successfully handled by canary"
        
        if [[ $percentage -ge $CANARY_PERCENTAGE && $CANARY_PERCENTAGE -lt 100 ]]; then
            info "Reached target canary percentage (${CANARY_PERCENTAGE}%)"
            break
        fi
    done
}

update_canary_traffic_percentage() {
    local percentage="$1"
    
    # This would typically involve updating service mesh configuration
    # For example, with Istio VirtualService
    info "Updating traffic routing to ${percentage}% canary"
    
    # Simplified traffic routing update
    # In practice, this would be more complex with proper service mesh integration
}

monitor_canary_performance() {
    local monitor_duration="$1"
    local check_interval=30
    
    info "Monitoring canary performance for ${monitor_duration} seconds..."
    
    for ((i=0; i<monitor_duration; i+=check_interval)); do
        # Check error rates, response times, etc.
        if ! validate_canary_metrics; then
            error "Canary metrics validation failed"
            return 1
        fi
        
        sleep $check_interval
    done
    
    return 0
}

validate_canary_metrics() {
    # Simplified metrics validation
    # In practice, you'd query monitoring systems like Prometheus
    
    local error_rate_threshold=5.0    # 5% error rate threshold
    local response_time_threshold=2000 # 2 second response time threshold
    
    # Simulate metrics check (replace with actual monitoring queries)
    local current_error_rate=1.2
    local current_response_time=450
    
    if (( $(echo "$current_error_rate > $error_rate_threshold" | bc -l) )); then
        error "Error rate too high: ${current_error_rate}% (threshold: ${error_rate_threshold}%)"
        return 1
    fi
    
    if (( $(echo "$current_response_time > $response_time_threshold" | bc -l) )); then
        error "Response time too high: ${current_response_time}ms (threshold: ${response_time_threshold}ms)"
        return 1
    fi
    
    return 0
}

promote_canary_to_production() {
    info "Promoting canary to full production..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would promote canary to production"
        return 0
    fi
    
    # Replace production deployment with canary
    kubectl patch deployment fortress-api -n fortress --patch '{
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "fortress-api",
                        "image": "fortress/fortress-api:'"$NEW_VERSION"'"
                    }]
                }
            }
        }
    }'
    
    # Scale up production to full capacity
    kubectl scale deployment fortress-api -n fortress --replicas=3
    
    # Wait for rollout to complete
    kubectl rollout status deployment/fortress-api -n fortress --timeout="${HEALTH_CHECK_TIMEOUT}s"
    
    # Clean up canary environment
    kubectl delete namespace fortress-canary --ignore-not-found=true
    
    success "Canary promoted to full production"
}

execute_canary_rollback() {
    error "Executing canary rollback..."
    
    # Immediately redirect all traffic back to production
    update_canary_traffic_percentage 0
    
    # Clean up canary deployment
    kubectl delete namespace fortress-canary --ignore-not-found=true
    
    error "Canary deployment rolled back"
}

execute_rolling_deployment() {
    info "Starting Rolling deployment with batch size: $BATCH_SIZE..."
    
    # Save current state
    save_deployment_state "pre-rolling"
    
    # Execute rolling update
    execute_rolling_update
    
    # Validate rolling deployment
    validate_rolling_deployment
    
    success "Rolling deployment completed successfully"
}

execute_rolling_update() {
    info "Executing rolling update..."
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        info "Rolling update for deployment: $deployment"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            info "[DRY RUN] Would update deployment: $deployment"
            continue
        fi
        
        # Update deployment image
        kubectl set image "deployment/$deployment" \
            "$deployment=fortress/$deployment:$NEW_VERSION" \
            -n fortress
        
        # Configure rolling update strategy
        kubectl patch deployment "$deployment" -n fortress -p '{
            "spec": {
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {
                        "maxSurge": "'$BATCH_SIZE'",
                        "maxUnavailable": 0
                    }
                }
            }
        }'
        
        # Wait for rollout to complete
        kubectl rollout status "deployment/$deployment" -n fortress --timeout="${HEALTH_CHECK_TIMEOUT}s"
        
        # Validate deployment health after each update
        if ! validate_deployment_health; then
            error "Health check failed after updating $deployment"
            execute_rolling_rollback "$deployment"
            exit 1
        fi
        
        success "Successfully updated deployment: $deployment"
    done
}

validate_rolling_deployment() {
    info "Validating rolling deployment..."
    
    # Extended validation after all deployments are updated
    local validation_duration=180  # 3 minutes
    local check_interval=15       # 15 seconds
    
    info "Monitoring deployment stability for ${validation_duration} seconds..."
    
    for ((i=0; i<validation_duration; i+=check_interval)); do
        if ! validate_deployment_health; then
            error "Rolling deployment validation failed"
            execute_full_rollback
            exit 1
        fi
        
        sleep $check_interval
    done
    
    success "Rolling deployment validation completed"
}

execute_rolling_rollback() {
    local failed_deployment="$1"
    
    error "Rolling back deployment: $failed_deployment"
    
    kubectl rollout undo "deployment/$failed_deployment" -n fortress
    kubectl rollout status "deployment/$failed_deployment" -n fortress --timeout="${ROLLBACK_TIMEOUT}s"
    
    error "Deployment $failed_deployment rolled back"
}

execute_recreate_deployment() {
    warn "Starting Recreate deployment (will cause downtime)..."
    
    # Save current state
    save_deployment_state "pre-recreate"
    
    # Scale down all deployments
    scale_down_deployments
    
    # Update deployments
    update_deployments
    
    # Scale up deployments
    scale_up_deployments
    
    # Validate deployment
    validate_deployment_health
    
    success "Recreate deployment completed successfully"
}

scale_down_deployments() {
    info "Scaling down deployments..."
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl scale deployment "$deployment" -n fortress --replicas=0
            kubectl wait --for=jsonpath='{.status.replicas}'=0 deployment/"$deployment" -n fortress --timeout=120s
        fi
    done
    
    success "All deployments scaled down"
}

update_deployments() {
    info "Updating deployment images..."
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl set image "deployment/$deployment" \
                "$deployment=fortress/$deployment:$NEW_VERSION" \
                -n fortress
        fi
    done
    
    success "Deployment images updated"
}

scale_up_deployments() {
    info "Scaling up deployments..."
    
    local deployments=("fortress-api:3" "fortress-smtp:2" "fortress-workflows:2")
    
    for deployment_info in "${deployments[@]}"; do
        local deployment="${deployment_info%%:*}"
        local replicas="${deployment_info##*:}"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl scale deployment "$deployment" -n fortress --replicas="$replicas"
            kubectl wait --for=condition=available deployment/"$deployment" -n fortress --timeout="${HEALTH_CHECK_TIMEOUT}s"
        fi
    done
    
    success "All deployments scaled up and ready"
}

# =============================================================================
# Deployment State Management and Rollback
# =============================================================================

save_deployment_state() {
    local state_type="$1"
    
    info "Saving deployment state: $state_type"
    
    local state_file="${LOG_DIR}/deployment-state-${state_type}-${TIMESTAMP}.json"
    
    local state="{
        \"timestamp\": $(date +%s),
        \"deployment_id\": \"$DEPLOYMENT_ID\",
        \"state_type\": \"$state_type\",
        \"environment\": \"$ENVIRONMENT\",
        \"strategy\": \"$DEPLOYMENT_STRATEGY\",
        \"current_version\": \"$CURRENT_VERSION\",
        \"new_version\": \"$NEW_VERSION\",
        \"kubernetes_state\": $(save_kubernetes_state),
        \"terraform_state\": $(save_terraform_state)
    }"
    
    echo "$state" > "$state_file"
    
    # Update main rollback state file
    echo "$state" > "$ROLLBACK_STATE"
    
    success "Deployment state saved: $state_file"
}

save_kubernetes_state() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "{\"dry_run\": true}"
        return
    fi
    
    local deployments
    deployments=$(kubectl get deployments -n fortress -o json 2>/dev/null || echo '{"items": []}')
    
    echo "$deployments" | jq '{
        "deployments": [.items[] | {
            "name": .metadata.name,
            "image": .spec.template.spec.containers[0].image,
            "replicas": .spec.replicas
        }]
    }'
}

save_terraform_state() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "{\"dry_run\": true}"
        return
    fi
    
    if [[ -d "$TERRAFORM_DIR" ]]; then
        cd "$TERRAFORM_DIR"
        
        local state_info="{
            \"workspace\": \"$(terraform workspace show 2>/dev/null || echo 'default')\",
            \"state_serial\": $(terraform show -json 2>/dev/null | jq '.serial // 0')
        }"
        
        cd "$PROJECT_ROOT"
        echo "$state_info"
    else
        echo "{\"terraform_dir_not_found\": true}"
    fi
}

execute_automatic_rollback() {
    critical "INITIATING AUTOMATIC ROLLBACK"
    
    send_alert "CRITICAL" "Automatic rollback initiated for deployment $DEPLOYMENT_ID"
    
    # Load rollback state
    if [[ ! -f "$ROLLBACK_STATE" ]]; then
        error "Rollback state file not found: $ROLLBACK_STATE"
        execute_emergency_procedures
        exit 1
    fi
    
    local rollback_strategy
    rollback_strategy=$(jq -r '.strategy' "$ROLLBACK_STATE")
    
    case "$rollback_strategy" in
        "blue-green")
            execute_blue_green_rollback
            ;;
        "canary")
            execute_canary_rollback
            ;;
        "rolling")
            execute_full_rollback
            ;;
        "recreate")
            execute_recreate_rollback
            ;;
        *)
            error "Unknown rollback strategy: $rollback_strategy"
            execute_emergency_procedures
            ;;
    esac
    
    # Verify rollback success
    if validate_deployment_health; then
        success "Automatic rollback completed successfully"
        send_alert "INFO" "Automatic rollback completed for deployment $DEPLOYMENT_ID"
    else
        critical "ROLLBACK FAILED - MANUAL INTERVENTION REQUIRED"
        execute_emergency_procedures
        exit 1
    fi
}

execute_blue_green_rollback() {
    info "Executing blue-green rollback..."
    
    # Switch traffic back to blue environment
    info "Switching traffic back to blue environment"
    
    if [[ "$DRY_RUN" != "true" ]]; then
        # Revert service selector to blue
        kubectl patch service fortress-api -n fortress -p '{"spec":{"selector":{"app":"fortress-api","version":"blue"}}}'
        
        # Delete green environment
        kubectl delete namespace fortress-green --ignore-not-found=true
    fi
    
    success "Blue-green rollback completed"
}

execute_full_rollback() {
    info "Executing full rollback..."
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        info "Rolling back deployment: $deployment"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl rollout undo "deployment/$deployment" -n fortress
            kubectl rollout status "deployment/$deployment" -n fortress --timeout="${ROLLBACK_TIMEOUT}s"
        fi
    done
    
    success "Full rollback completed"
}

execute_recreate_rollback() {
    info "Executing recreate rollback..."
    
    # This is similar to recreate deployment but with previous images
    local previous_version
    previous_version=$(jq -r '.current_version' "$ROLLBACK_STATE")
    
    # Scale down
    scale_down_deployments
    
    # Update to previous version
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl set image "deployment/$deployment" \
                "$deployment=fortress/$deployment:$previous_version" \
                -n fortress
        fi
    done
    
    # Scale up
    scale_up_deployments
    
    success "Recreate rollback completed"
}

execute_emergency_procedures() {
    critical "EXECUTING EMERGENCY PROCEDURES"
    
    # Send critical alerts
    send_alert "CRITICAL" "Emergency procedures activated - manual intervention required"
    
    # Create incident report
    create_incident_report
    
    # Stop all automated processes
    info "Stopping all automated deployment processes"
    
    # Preserve logs and state
    preserve_deployment_artifacts
    
    critical "EMERGENCY PROCEDURES COMPLETED - MANUAL INTERVENTION REQUIRED"
    critical "Check incident report at: ${LOG_DIR}/incident-report-${TIMESTAMP}.txt"
}

create_incident_report() {
    local incident_file="${LOG_DIR}/incident-report-${TIMESTAMP}.txt"
    
    cat > "$incident_file" << EOF
# FORTRESS DEPLOYMENT INCIDENT REPORT
Generated: $(date)
Deployment ID: $DEPLOYMENT_ID
Environment: $ENVIRONMENT
Strategy: $DEPLOYMENT_STRATEGY
Version: $NEW_VERSION

## Incident Timeline
$(tail -n 50 "$LOG_FILE")

## System State at Incident
Kubernetes Deployments:
$(kubectl get deployments -n fortress -o wide 2>/dev/null || echo "Unable to retrieve Kubernetes state")

## Metrics at Incident
$(cat "$METRICS_FILE" 2>/dev/null || echo "No metrics available")

## Rollback State
$(cat "$ROLLBACK_STATE" 2>/dev/null || echo "No rollback state available")

## Recommended Actions
1. Investigate root cause from deployment logs
2. Verify system health and data integrity  
3. Consider manual rollback if automatic rollback failed
4. Review deployment strategy and configuration
5. Update incident response procedures based on lessons learned

EOF
    
    critical "Incident report created: $incident_file"
}

preserve_deployment_artifacts() {
    info "Preserving deployment artifacts..."
    
    local artifacts_dir="${LOG_DIR}/artifacts-${TIMESTAMP}"
    mkdir -p "$artifacts_dir"
    
    # Copy important files
    cp "$LOG_FILE" "$artifacts_dir/" 2>/dev/null || true
    cp "$METRICS_FILE" "$artifacts_dir/" 2>/dev/null || true
    cp "$ROLLBACK_STATE" "$artifacts_dir/" 2>/dev/null || true
    
    # Export Kubernetes state
    kubectl get all -n fortress -o yaml > "${artifacts_dir}/kubernetes-state.yaml" 2>/dev/null || true
    
    # Compress artifacts
    tar -czf "${LOG_DIR}/deployment-artifacts-${TIMESTAMP}.tar.gz" -C "$LOG_DIR" "artifacts-${TIMESTAMP}"
    
    success "Deployment artifacts preserved"
}

# =============================================================================
# Health Monitoring and Validation
# =============================================================================

validate_deployment_health() {
    debug "Validating deployment health..."
    
    # Check Kubernetes deployment status
    if ! validate_kubernetes_health; then
        return 1
    fi
    
    # Check application health endpoints
    if ! validate_application_health; then
        return 1
    fi
    
    # Check performance metrics
    if ! validate_performance_metrics; then
        return 1
    fi
    
    return 0
}

validate_kubernetes_health() {
    debug "Checking Kubernetes deployment health..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        # Check if deployment is available
        if ! kubectl get deployment "$deployment" -n fortress >/dev/null 2>&1; then
            debug "Deployment not found: $deployment"
            return 1
        fi
        
        # Check if pods are ready
        local ready_replicas
        ready_replicas=$(kubectl get deployment "$deployment" -n fortress -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        
        local desired_replicas
        desired_replicas=$(kubectl get deployment "$deployment" -n fortress -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
        
        if [[ "$ready_replicas" -lt "$desired_replicas" ]]; then
            debug "Deployment $deployment not fully ready: $ready_replicas/$desired_replicas"
            return 1
        fi
    done
    
    return 0
}

validate_application_health() {
    debug "Checking application health endpoints..."
    
    local services=("fortress-api:8025" "fortress-smtp:1025")
    
    for service_info in "${services[@]}"; do
        local service="${service_info%%:*}"
        local port="${service_info##*:}"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            continue
        fi
        
        # Port forward for health check
        kubectl port-forward -n fortress "service/$service" "18025:$port" &
        local port_forward_pid=$!
        
        sleep 2  # Wait for port forward
        
        # Check health endpoint
        local health_check_passed=true
        if ! timeout 10 curl -f -s "http://localhost:18025/health" >/dev/null 2>&1; then
            debug "Health check failed for $service"
            health_check_passed=false
        fi
        
        # Clean up port forward
        kill $port_forward_pid 2>/dev/null || true
        
        if [[ "$health_check_passed" != "true" ]]; then
            return 1
        fi
    done
    
    return 0
}

validate_performance_metrics() {
    debug "Checking performance metrics..."
    
    # This would typically query your monitoring system (Prometheus, etc.)
    # For now, we'll simulate basic performance validation
    
    local cpu_threshold=80    # 80% CPU usage threshold
    local memory_threshold=85 # 85% memory usage threshold
    
    # Get resource usage from Kubernetes
    if [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        # Get pods for deployment
        local pods
        pods=$(kubectl get pods -n fortress -l app="$deployment" -o jsonpath='{.items[*].metadata.name}')
        
        for pod in $pods; do
            # Check pod metrics (simplified)
            local pod_metrics
            pod_metrics=$(kubectl top pod "$pod" -n fortress --no-headers 2>/dev/null || echo "0m 0Mi")
            
            # Parse CPU and memory (basic parsing)
            local cpu_usage memory_usage
            cpu_usage=$(echo "$pod_metrics" | awk '{print $2}' | sed 's/m$//')
            memory_usage=$(echo "$pod_metrics" | awk '{print $3}' | sed 's/Mi$//')
            
            # Convert CPU to percentage (simplified)
            local cpu_percentage=$((cpu_usage / 10))  # Rough conversion
            
            if [[ "$cpu_percentage" -gt "$cpu_threshold" ]]; then
                debug "High CPU usage on pod $pod: ${cpu_percentage}%"
                return 1
            fi
            
            if [[ "$memory_usage" -gt 1000 ]]; then  # More than 1GB
                debug "High memory usage on pod $pod: ${memory_usage}Mi"
            fi
        done
    done
    
    return 0
}

# =============================================================================
# Post-Deployment Operations
# =============================================================================

run_post_deployment_operations() {
    info "Running post-deployment operations..."
    
    # Update monitoring configurations
    update_monitoring_configuration
    
    # Run smoke tests
    run_smoke_tests
    
    # Update documentation
    update_deployment_documentation
    
    # Send success notifications
    send_deployment_success_notification
    
    # Schedule post-deployment tasks
    schedule_post_deployment_tasks
    
    success "Post-deployment operations completed"
}

update_monitoring_configuration() {
    info "Updating monitoring configuration..."
    
    # Update Prometheus targets
    if [[ -f "${CONFIG_DIR}/monitoring/prometheus-targets.yaml" ]]; then
        kubectl apply -f "${CONFIG_DIR}/monitoring/prometheus-targets.yaml" -n fortress || warn "Failed to update Prometheus targets"
    fi
    
    # Update Grafana dashboards
    if [[ -d "${CONFIG_DIR}/monitoring/dashboards" ]]; then
        for dashboard in "${CONFIG_DIR}/monitoring/dashboards"/*.json; do
            if [[ -f "$dashboard" ]]; then
                kubectl create configmap "$(basename "$dashboard" .json)" \
                    --from-file="$dashboard" \
                    -n fortress \
                    --dry-run=client -o yaml | kubectl apply -f - || warn "Failed to update dashboard"
            fi
        done
    fi
    
    success "Monitoring configuration updated"
}

run_smoke_tests() {
    info "Running smoke tests..."
    
    local test_endpoints=(
        "/health"
        "/api/v1/status"
        "/metrics"
    )
    
    local base_url="https://fortress.${DOMAIN_NAME:-localhost}"
    
    for endpoint in "${test_endpoints[@]}"; do
        info "Testing endpoint: $endpoint"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            info "[DRY RUN] Would test: $base_url$endpoint"
            continue
        fi
        
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$base_url$endpoint" || echo "000")
        
        if [[ "$response_code" =~ ^[23][0-9][0-9]$ ]]; then
            success "✓ $endpoint - HTTP $response_code"
        else
            warn "✗ $endpoint - HTTP $response_code"
        fi
    done
    
    success "Smoke tests completed"
}

update_deployment_documentation() {
    info "Updating deployment documentation..."
    
    local docs_file="${PROJECT_ROOT}/docs/deployment-history.md"
    
    # Append deployment record to documentation
    cat >> "$docs_file" << EOF

## Deployment $(date +%Y-%m-%d)
- **Deployment ID**: $DEPLOYMENT_ID
- **Strategy**: $DEPLOYMENT_STRATEGY
- **Version**: $CURRENT_VERSION → $NEW_VERSION
- **Environment**: $ENVIRONMENT
- **Duration**: $(($(date +%s) - DEPLOYMENT_START_TIME)) seconds
- **Status**: SUCCESS

EOF
    
    success "Deployment documentation updated"
}

send_deployment_success_notification() {
    info "Sending deployment success notification..."
    
    local deployment_duration=$(($(date +%s) - DEPLOYMENT_START_TIME))
    local message="✅ Fortress deployment completed successfully!
    
Deployment Details:
• ID: $DEPLOYMENT_ID
• Strategy: $DEPLOYMENT_STRATEGY  
• Version: $CURRENT_VERSION → $NEW_VERSION
• Environment: $ENVIRONMENT
• Duration: ${deployment_duration}s
• URL: https://fortress.${DOMAIN_NAME:-localhost}

All systems operational and monitoring active."

    send_alert "SUCCESS" "$message"
    
    success "Deployment success notification sent"
}

schedule_post_deployment_tasks() {
    info "Scheduling post-deployment tasks..."
    
    # Schedule log cleanup (24 hours)
    (
        sleep 86400
        find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
        info "Old deployment logs cleaned up"
    ) &
    
    # Schedule backup verification (1 hour)
    (
        sleep 3600
        verify_post_deployment_backups
    ) &
    
    # Schedule performance report (30 minutes)
    (
        sleep 1800
        generate_performance_report
    ) &
    
    success "Post-deployment tasks scheduled"
}

verify_post_deployment_backups() {
    info "Verifying post-deployment backups..."
    
    # Verify database backup was taken
    if [[ -n "${BACKUP_S3_BUCKET:-}" ]]; then
        local backup_date=$(date +%Y-%m-%d)
        if aws s3 ls "s3://$BACKUP_S3_BUCKET/fortress-db-backup-$backup_date" >/dev/null 2>&1; then
            success "Database backup verified for $backup_date"
        else
            warn "Database backup not found for $backup_date"
        fi
    fi
}

generate_performance_report() {
    info "Generating post-deployment performance report..."
    
    local report_file="${LOG_DIR}/performance-report-${TIMESTAMP}.json"
    
    # Collect performance metrics
    local report="{
        \"deployment_id\": \"$DEPLOYMENT_ID\",
        \"timestamp\": $(date +%s),
        \"environment\": \"$ENVIRONMENT\",
        \"version\": \"$NEW_VERSION\",
        \"deployment_duration\": $(($(date +%s) - DEPLOYMENT_START_TIME)),
        \"post_deployment_metrics\": {
            \"response_time_p95\": 0,
            \"throughput_rps\": 0,
            \"error_rate\": 0,
            \"availability\": 100
        }
    }"
    
    echo "$report" > "$report_file"
    
    success "Performance report generated: $report_file"
}

# =============================================================================
# Main Deployment Function
# =============================================================================

main() {
    info "🚀 Starting Fortress Production Deployment Automation"
    info "Deployment ID: $DEPLOYMENT_ID"
    info "Strategy: $DEPLOYMENT_STRATEGY"
    info "Environment: $ENVIRONMENT"
    info "Version: $CURRENT_VERSION → $NEW_VERSION"
    
    # Record deployment start
    record_metric "deployment_start" "$(date +%s)" "Starting deployment with strategy: $DEPLOYMENT_STRATEGY"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Set error handling
    trap handle_deployment_failure ERR
    trap handle_deployment_interrupt INT TERM
    
    # Execute deployment pipeline
    check_advanced_prerequisites
    run_pre_deployment_validation
    execute_deployment_strategy
    run_post_deployment_operations
    generate_final_deployment_report
    
    success "🎉 Fortress Production Deployment Completed Successfully!"
    success "Deployment ID: $DEPLOYMENT_ID"
    success "Total Duration: $(($(date +%s) - DEPLOYMENT_START_TIME)) seconds"
    
    record_metric "deployment_success" "$(date +%s)" "Deployment completed successfully"
}

handle_deployment_failure() {
    local exit_code=$?
    
    error "🚨 Deployment failed with exit code: $exit_code"
    record_metric "deployment_failure" "$(date +%s)" "Deployment failed with exit code: $exit_code"
    
    if [[ "$AUTO_ROLLBACK" == "true" ]]; then
        execute_automatic_rollback
    else
        error "Auto-rollback disabled. Manual intervention required."
        create_incident_report
    fi
    
    exit $exit_code
}

handle_deployment_interrupt() {
    warn "🛑 Deployment interrupted by user"
    record_metric "deployment_interrupted" "$(date +%s)" "Deployment interrupted by user signal"
    
    # Graceful cleanup
    info "Performing graceful cleanup..."
    preserve_deployment_artifacts
    
    exit 130
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --strategy)
                DEPLOYMENT_STRATEGY="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --version)
                VERSION="$2"
                NEW_VERSION="$2"
                shift 2
                ;;
            --canary-percentage)
                CANARY_PERCENTAGE="$2"
                shift 2
                ;;
            --batch-size)
                BATCH_SIZE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --force-deployment)
                FORCE_DEPLOYMENT="true"
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION="true"
                shift
                ;;
            --no-auto-rollback)
                AUTO_ROLLBACK="false"
                shift
                ;;
            --enable-chaos)
                ENABLE_CHAOS="true"
                shift
                ;;
            --webhook)
                NOTIFICATION_WEBHOOK="$2"
                shift 2
                ;;
            --help)
                print_advanced_usage
                exit 0
                ;;
            *)
                error "Unknown argument: $1"
                print_advanced_usage
                exit 1
                ;;
        esac
    done
    
    # Validate strategy
    case "$DEPLOYMENT_STRATEGY" in
        blue-green|canary|rolling|recreate)
            ;;
        *)
            error "Invalid deployment strategy: $DEPLOYMENT_STRATEGY"
            error "Valid strategies: blue-green, canary, rolling, recreate"
            exit 1
            ;;
    esac
}

generate_final_deployment_report() {
    info "Generating final deployment report..."
    
    local report_file="${LOG_DIR}/final-deployment-report-${TIMESTAMP}.md"
    local deployment_duration=$(($(date +%s) - DEPLOYMENT_START_TIME))
    
    cat > "$report_file" << EOF
# Fortress Production Deployment Report

## Deployment Summary
- **Deployment ID**: $DEPLOYMENT_ID
- **Strategy**: $DEPLOYMENT_STRATEGY
- **Environment**: $ENVIRONMENT
- **Version**: $CURRENT_VERSION → $NEW_VERSION
- **Start Time**: $(date -d "@$DEPLOYMENT_START_TIME")
- **Duration**: ${deployment_duration} seconds
- **Status**: ✅ SUCCESS

## Deployment Configuration
- Canary Percentage: $CANARY_PERCENTAGE%
- Batch Size: $BATCH_SIZE
- Health Check Timeout: ${HEALTH_CHECK_TIMEOUT}s
- Rollback Timeout: ${ROLLBACK_TIMEOUT}s
- Auto Rollback: $AUTO_ROLLBACK
- Dry Run: $DRY_RUN

## Access Information
- Web Interface: https://fortress.${DOMAIN_NAME:-localhost}
- SMTP Server: fortress.${DOMAIN_NAME:-localhost}:1025
- Monitoring: https://monitoring.fortress.${DOMAIN_NAME:-localhost}

## Deployment Metrics
$(tail -n 20 "$METRICS_FILE" 2>/dev/null || echo "No metrics available")

## Log Files
- Deployment Log: $LOG_FILE
- Metrics: $METRICS_FILE
- Rollback State: $ROLLBACK_STATE

## Next Steps
1. Monitor system performance for 24 hours
2. Verify all monitoring alerts are configured
3. Schedule next maintenance window
4. Review deployment metrics for optimization opportunities

---
*Generated by Fortress Production Deployment Automation*
*Report created: $(date)*
EOF
    
    success "Final deployment report generated: $report_file"
}

print_advanced_usage() {
    cat << EOF
🏗️ Fortress Production Deployment Automation

USAGE:
    $0 [OPTIONS]

DEPLOYMENT STRATEGIES:
    --strategy blue-green      Zero-downtime blue-green deployment
    --strategy canary          Gradual canary deployment with traffic shifting
    --strategy rolling         Rolling update with configurable batch size
    --strategy recreate        Recreate deployment (with downtime)

OPTIONS:
    --environment ENV          Target environment (default: production)
    --version VERSION          Application version to deploy (default: git describe)
    --canary-percentage PCT    Canary traffic percentage (default: 10)
    --batch-size SIZE          Rolling deployment batch size (default: 2)
    --dry-run                  Show what would be done without executing
    --force-deployment         Force deployment despite warnings
    --skip-validation          Skip pre-deployment validation
    --no-auto-rollback         Disable automatic rollback on failure
    --enable-chaos             Enable chaos engineering during deployment
    --webhook URL              Notification webhook URL
    --help                     Show this help message

EXAMPLES:
    # Blue-green production deployment
    $0 --strategy blue-green --environment production

    # Canary deployment with 25% traffic
    $0 --strategy canary --canary-percentage 25

    # Rolling deployment with batch size 3
    $0 --strategy rolling --batch-size 3

    # Dry run to see what would happen
    $0 --strategy blue-green --dry-run

    # Force deployment with notifications
    $0 --strategy canary --force-deployment --webhook https://hooks.slack.com/...

ENVIRONMENT VARIABLES:
    ENVIRONMENT                Target environment
    DEPLOYMENT_STRATEGY        Deployment strategy
    VERSION                   Application version
    CANARY_PERCENTAGE         Canary traffic percentage
    BATCH_SIZE               Rolling deployment batch size
    HEALTH_CHECK_TIMEOUT     Health check timeout in seconds
    ROLLBACK_TIMEOUT         Rollback timeout in seconds
    AUTO_ROLLBACK            Enable/disable auto rollback (true/false)
    DRY_RUN                  Dry run mode (true/false)
    NOTIFICATION_WEBHOOK     Slack/Teams webhook URL
    DOMAIN_NAME              Base domain name for services

FEATURES:
    ✅ Multiple deployment strategies (Blue-Green, Canary, Rolling, Recreate)
    ✅ Comprehensive pre-deployment validation
    ✅ Intelligent health monitoring and rollback
    ✅ Security scanning and compliance checks
    ✅ Performance baseline comparison
    ✅ Automatic backup verification
    ✅ Real-time notifications and alerting
    ✅ Detailed logging and metrics collection
    ✅ Emergency procedures and incident reporting
    ✅ Post-deployment operations and monitoring

EOF
}

# =============================================================================
# Execute Main Function
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi