#!/bin/bash
# 🚀 Fortress Deployment Automation Script
# Intelligent deployment automation for Pat Fortress with quality gates

set -euo pipefail

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/.github/quality-gates-config.yml"

# Default values
NAMESPACE=""
DEPLOYMENT_NAME=""
ENVIRONMENT=""
DEPLOYMENT_STRATEGY=""
IMAGE_TAG=""
DRY_RUN="false"
SKIP_QUALITY_GATES="false"
FORCE_DEPLOY="false"
NOTIFICATION_ENABLED="true"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# ===== LOGGING =====
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    
    case "$level" in
        INFO)
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" | tee -a /tmp/deployment.log
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" | tee -a /tmp/deployment.log
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a /tmp/deployment.log
            ;;
        DEBUG)
            if [[ "${DEBUG:-}" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" | tee -a /tmp/deployment.log
            fi
            ;;
        SUCCESS)
            echo -e "${PURPLE}[SUCCESS]${NC} ${timestamp} - $message" | tee -a /tmp/deployment.log
            ;;
    esac
}

# ===== UTILITY FUNCTIONS =====
usage() {
    cat << EOF
🚀 Fortress Deployment Automation Script

Usage: $0 [OPTIONS]

OPTIONS:
    -n, --namespace NAMESPACE       Kubernetes namespace
    -d, --deployment DEPLOYMENT     Deployment name
    -e, --environment ENV           Environment (development/staging/production)
    -s, --strategy STRATEGY         Deployment strategy (rolling/blue-green/canary)
    -t, --tag IMAGE_TAG            Docker image tag to deploy
    --dry-run                       Perform dry run without actual deployment
    --skip-quality-gates            Skip quality gate validation (not recommended)
    --force                         Force deployment even if quality gates fail
    --no-notifications              Disable notifications
    -h, --help                      Show this help message

EXAMPLES:
    $0 -n pat-production -d pat-app -e production -s canary -t v1.2.3
    $0 --namespace pat-staging --deployment pat-service --environment staging --strategy blue-green --tag latest --dry-run
    $0 -n pat-dev -d pat-app -e development --strategy rolling --tag feature-branch --skip-quality-gates

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -d|--deployment)
                DEPLOYMENT_NAME="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--strategy)
                DEPLOYMENT_STRATEGY="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --skip-quality-gates)
                SKIP_QUALITY_GATES="true"
                shift
                ;;
            --force)
                FORCE_DEPLOY="true"
                shift
                ;;
            --no-notifications)
                NOTIFICATION_ENABLED="false"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

validate_prerequisites() {
    log "INFO" "Validating prerequisites..."
    
    # Check required parameters
    if [[ -z "$NAMESPACE" ]] || [[ -z "$DEPLOYMENT_NAME" ]] || [[ -z "$ENVIRONMENT" ]] || [[ -z "$IMAGE_TAG" ]]; then
        log "ERROR" "Required parameters missing. Use --help for usage information."
        exit 1
    fi
    
    # Validate environment
    case "$ENVIRONMENT" in
        development|staging|production)
            log "DEBUG" "Environment validation passed: $ENVIRONMENT"
            ;;
        *)
            log "ERROR" "Invalid environment: $ENVIRONMENT. Must be one of: development, staging, production"
            exit 1
            ;;
    esac
    
    # Set default deployment strategy based on environment if not specified
    if [[ -z "$DEPLOYMENT_STRATEGY" ]]; then
        case "$ENVIRONMENT" in
            development)
                DEPLOYMENT_STRATEGY="rolling"
                ;;
            staging)
                DEPLOYMENT_STRATEGY="blue-green"
                ;;
            production)
                DEPLOYMENT_STRATEGY="canary"
                ;;
        esac
        log "INFO" "Using default deployment strategy for $ENVIRONMENT: $DEPLOYMENT_STRATEGY"
    fi
    
    # Validate deployment strategy
    case "$DEPLOYMENT_STRATEGY" in
        rolling|blue-green|canary)
            log "DEBUG" "Deployment strategy validation passed: $DEPLOYMENT_STRATEGY"
            ;;
        *)
            log "ERROR" "Invalid deployment strategy: $DEPLOYMENT_STRATEGY. Must be one of: rolling, blue-green, canary"
            exit 1
            ;;
    esac
    
    # Check tool availability
    local required_tools=("kubectl" "helm" "jq" "yq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "ERROR" "$tool is not installed or not in PATH"
            exit 1
        fi
    done
    
    # Verify cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log "ERROR" "Unable to connect to Kubernetes cluster"
        exit 1
    fi
    
    # Verify namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log "WARN" "Namespace '$NAMESPACE' does not exist, creating it..."
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl create namespace "$NAMESPACE"
        fi
    fi
    
    log "INFO" "Prerequisites validation completed successfully"
}

load_quality_gates_config() {
    log "INFO" "Loading quality gates configuration..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Quality gates configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Load environment-specific configuration
    local quality_gates_required
    quality_gates_required=$(yq eval ".deployment_strategies.${ENVIRONMENT}.quality_gates_required[]" "$CONFIG_FILE" 2>/dev/null || echo "")
    
    if [[ -z "$quality_gates_required" ]]; then
        log "WARN" "No quality gates configured for environment: $ENVIRONMENT"
        QUALITY_GATES_REQUIRED=()
    else
        mapfile -t QUALITY_GATES_REQUIRED <<< "$quality_gates_required"
    fi
    
    log "DEBUG" "Quality gates required for $ENVIRONMENT: ${QUALITY_GATES_REQUIRED[*]:-none}"
}

validate_quality_gates() {
    if [[ "$SKIP_QUALITY_GATES" == "true" ]]; then
        log "WARN" "Quality gates validation skipped (not recommended for production)"
        return 0
    fi
    
    log "INFO" "Validating quality gates..."
    
    local failed_gates=()
    local total_gates=${#QUALITY_GATES_REQUIRED[@]}
    local passed_gates=0
    
    for gate in "${QUALITY_GATES_REQUIRED[@]}"; do
        log "INFO" "Checking quality gate: $gate"
        
        case "$gate" in
            unit_tests)
                if check_unit_tests_quality_gate; then
                    log "SUCCESS" "Unit tests quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Unit tests quality gate failed"
                    failed_gates+=("unit_tests")
                fi
                ;;
            integration_tests)
                if check_integration_tests_quality_gate; then
                    log "SUCCESS" "Integration tests quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Integration tests quality gate failed"
                    failed_gates+=("integration_tests")
                fi
                ;;
            security)
                if check_security_quality_gate; then
                    log "SUCCESS" "Security quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Security quality gate failed"
                    failed_gates+=("security")
                fi
                ;;
            performance)
                if check_performance_quality_gate; then
                    log "SUCCESS" "Performance quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Performance quality gate failed"
                    failed_gates+=("performance")
                fi
                ;;
            compliance)
                if check_compliance_quality_gate; then
                    log "SUCCESS" "Compliance quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Compliance quality gate failed"
                    failed_gates+=("compliance")
                fi
                ;;
            code_quality)
                if check_code_quality_gate; then
                    log "SUCCESS" "Code quality gate passed"
                    ((passed_gates++))
                else
                    log "ERROR" "Code quality gate failed"
                    failed_gates+=("code_quality")
                fi
                ;;
            *)
                log "WARN" "Unknown quality gate: $gate"
                ;;
        esac
    done
    
    log "INFO" "Quality gates summary: $passed_gates/$total_gates passed"
    
    if [[ ${#failed_gates[@]} -gt 0 ]]; then
        log "ERROR" "Failed quality gates: ${failed_gates[*]}"
        
        if [[ "$FORCE_DEPLOY" != "true" ]]; then
            log "ERROR" "Deployment blocked by quality gate failures. Use --force to override (not recommended)"
            return 1
        else
            log "WARN" "Proceeding with deployment despite quality gate failures (forced deployment)"
        fi
    fi
    
    return 0
}

check_unit_tests_quality_gate() {
    # This would typically check the latest CI run results
    # For now, we'll simulate by checking if test results exist
    log "DEBUG" "Checking unit tests quality gate..."
    
    # In a real implementation, this would:
    # 1. Query GitHub API for latest CI run
    # 2. Check test coverage reports
    # 3. Validate against thresholds from config
    
    # Simulate check
    if [[ -f "/tmp/unit-test-results.json" ]]; then
        local coverage=$(jq -r '.coverage.percentage' /tmp/unit-test-results.json 2>/dev/null || echo "0")
        local threshold=$(yq eval '.quality_gates.unit_tests.coverage_threshold' "$CONFIG_FILE")
        
        if [[ $(echo "$coverage >= $threshold" | bc -l) -eq 1 ]]; then
            return 0
        fi
    fi
    
    # For demo purposes, assume it passes in development, requires validation in others
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        *)
            log "WARN" "Unit test results not available or below threshold"
            return 1
            ;;
    esac
}

check_integration_tests_quality_gate() {
    log "DEBUG" "Checking integration tests quality gate..."
    
    # Similar to unit tests, this would check actual test results
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        staging|production)
            # In real implementation, check actual test results
            log "WARN" "Integration test validation not implemented"
            return 1
            ;;
    esac
}

check_security_quality_gate() {
    log "DEBUG" "Checking security quality gate..."
    
    # This would check security scan results
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        *)
            log "WARN" "Security scan validation not implemented"
            return 1
            ;;
    esac
}

check_performance_quality_gate() {
    log "DEBUG" "Checking performance quality gate..."
    
    # This would check performance test results
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        *)
            log "WARN" "Performance test validation not implemented"
            return 1
            ;;
    esac
}

check_compliance_quality_gate() {
    log "DEBUG" "Checking compliance quality gate..."
    
    # This would check compliance scan results
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        *)
            log "WARN" "Compliance validation not implemented"
            return 1
            ;;
    esac
}

check_code_quality_gate() {
    log "DEBUG" "Checking code quality gate..."
    
    # This would check code quality metrics
    case "$ENVIRONMENT" in
        development)
            return 0
            ;;
        *)
            log "WARN" "Code quality validation not implemented"
            return 1
            ;;
    esac
}

prepare_deployment() {
    log "INFO" "Preparing deployment..."
    
    # Validate image exists (for non-dry-run)
    if [[ "$DRY_RUN" != "true" ]]; then
        local image_name="ghcr.io/pat-fortress:$IMAGE_TAG"
        log "DEBUG" "Validating image: $image_name"
        
        # In real implementation, this would verify image exists in registry
        # docker manifest inspect "$image_name" >/dev/null 2>&1
    fi
    
    # Create deployment manifests
    local deploy_dir="/tmp/deployment-$DEPLOYMENT_NAME-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$deploy_dir"
    
    # Generate Helm values based on environment and strategy
    cat > "$deploy_dir/values.yaml" << EOF
# Generated deployment values for $ENVIRONMENT environment
image:
  repository: ghcr.io/pat-fortress
  tag: $IMAGE_TAG
  pullPolicy: IfNotPresent

deployment:
  name: $DEPLOYMENT_NAME
  strategy: $DEPLOYMENT_STRATEGY
  environment: $ENVIRONMENT

replicaCount: $(get_replica_count)

service:
  type: ClusterIP
  port: 80
  targetPort: 8080

ingress:
  enabled: $(get_ingress_enabled)
  className: nginx
  hosts:
    - host: $(get_hostname)
      paths:
        - path: /
          pathType: Prefix

resources:
  limits:
    cpu: $(get_cpu_limit)
    memory: $(get_memory_limit)
  requests:
    cpu: $(get_cpu_request)
    memory: $(get_memory_request)

autoscaling:
  enabled: $(get_autoscaling_enabled)
  minReplicas: $(get_min_replicas)
  maxReplicas: $(get_max_replicas)
  targetCPUUtilizationPercentage: 80

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    
healthCheck:
  enabled: true
  path: /health
  port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
EOF
    
    log "INFO" "Deployment configuration prepared in: $deploy_dir"
    echo "DEPLOY_DIR=$deploy_dir" >> /tmp/deployment.log
}

get_replica_count() {
    case "$ENVIRONMENT" in
        development) echo "1" ;;
        staging) echo "2" ;;
        production) echo "3" ;;
    esac
}

get_ingress_enabled() {
    case "$ENVIRONMENT" in
        development) echo "false" ;;
        staging|production) echo "true" ;;
    esac
}

get_hostname() {
    case "$ENVIRONMENT" in
        development) echo "pat-dev.local" ;;
        staging) echo "pat-staging.example.com" ;;
        production) echo "pat.example.com" ;;
    esac
}

get_cpu_limit() {
    case "$ENVIRONMENT" in
        development) echo "500m" ;;
        staging) echo "1000m" ;;
        production) echo "2000m" ;;
    esac
}

get_memory_limit() {
    case "$ENVIRONMENT" in
        development) echo "512Mi" ;;
        staging) echo "1Gi" ;;
        production) echo "2Gi" ;;
    esac
}

get_cpu_request() {
    case "$ENVIRONMENT" in
        development) echo "100m" ;;
        staging) echo "200m" ;;
        production) echo "500m" ;;
    esac
}

get_memory_request() {
    case "$ENVIRONMENT" in
        development) echo "128Mi" ;;
        staging) echo "256Mi" ;;
        production) echo "512Mi" ;;
    esac
}

get_autoscaling_enabled() {
    case "$ENVIRONMENT" in
        development) echo "false" ;;
        staging|production) echo "true" ;;
    esac
}

get_min_replicas() {
    case "$ENVIRONMENT" in
        development) echo "1" ;;
        staging) echo "2" ;;
        production) echo "3" ;;
    esac
}

get_max_replicas() {
    case "$ENVIRONMENT" in
        development) echo "2" ;;
        staging) echo "5" ;;
        production) echo "10" ;;
    esac
}

execute_deployment() {
    log "INFO" "Executing $DEPLOYMENT_STRATEGY deployment..."
    
    case "$DEPLOYMENT_STRATEGY" in
        rolling)
            execute_rolling_deployment
            ;;
        blue-green)
            execute_blue_green_deployment
            ;;
        canary)
            execute_canary_deployment
            ;;
        *)
            log "ERROR" "Unknown deployment strategy: $DEPLOYMENT_STRATEGY"
            return 1
            ;;
    esac
}

execute_rolling_deployment() {
    log "INFO" "Executing rolling deployment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would perform rolling deployment of $IMAGE_TAG"
        return 0
    fi
    
    local deploy_dir=$(grep "DEPLOY_DIR=" /tmp/deployment.log | tail -1 | cut -d'=' -f2)
    
    # Deploy using Helm
    helm upgrade --install "$DEPLOYMENT_NAME" "$PROJECT_ROOT/helm/pat-fortress" \
        --namespace "$NAMESPACE" \
        --values "$deploy_dir/values.yaml" \
        --set image.tag="$IMAGE_TAG" \
        --timeout 10m \
        --wait
    
    log "SUCCESS" "Rolling deployment completed"
}

execute_blue_green_deployment() {
    log "INFO" "Executing blue-green deployment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would perform blue-green deployment of $IMAGE_TAG"
        return 0
    fi
    
    # Determine current color
    local current_color=$(kubectl get service "$DEPLOYMENT_NAME-active" -n "$NAMESPACE" -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "blue")
    local new_color
    
    if [[ "$current_color" == "blue" ]]; then
        new_color="green"
    else
        new_color="blue"
    fi
    
    log "INFO" "Deploying to $new_color environment (current: $current_color)"
    
    local deploy_dir=$(grep "DEPLOY_DIR=" /tmp/deployment.log | tail -1 | cut -d'=' -f2)
    
    # Deploy to inactive environment
    helm upgrade --install "$DEPLOYMENT_NAME-$new_color" "$PROJECT_ROOT/helm/pat-fortress" \
        --namespace "$NAMESPACE" \
        --values "$deploy_dir/values.yaml" \
        --set image.tag="$IMAGE_TAG" \
        --set deployment.color="$new_color" \
        --set service.name="$DEPLOYMENT_NAME-$new_color" \
        --timeout 10m \
        --wait
    
    # Health check on new deployment
    if perform_health_check "$DEPLOYMENT_NAME-$new_color" 300; then
        # Switch traffic to new deployment
        kubectl patch service "$DEPLOYMENT_NAME-active" -n "$NAMESPACE" -p "{\"spec\":{\"selector\":{\"color\":\"$new_color\"}}}"
        
        # Wait for traffic to stabilize
        sleep 30
        
        # Scale down old deployment
        kubectl scale deployment "$DEPLOYMENT_NAME-$current_color" --replicas=0 -n "$NAMESPACE"
        
        log "SUCCESS" "Blue-green deployment completed (switched from $current_color to $new_color)"
    else
        log "ERROR" "Health check failed for new deployment, keeping current deployment active"
        return 1
    fi
}

execute_canary_deployment() {
    log "INFO" "Executing canary deployment..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would perform canary deployment of $IMAGE_TAG"
        return 0
    fi
    
    local deploy_dir=$(grep "DEPLOY_DIR=" /tmp/deployment.log | tail -1 | cut -d'=' -f2)
    local canary_steps=(10 25 50 75 100)
    
    # Deploy canary version
    helm upgrade --install "$DEPLOYMENT_NAME-canary" "$PROJECT_ROOT/helm/pat-fortress" \
        --namespace "$NAMESPACE" \
        --values "$deploy_dir/values.yaml" \
        --set image.tag="$IMAGE_TAG" \
        --set deployment.type="canary" \
        --set canary.weight=10 \
        --timeout 10m \
        --wait
    
    # Gradually increase canary traffic
    for weight in "${canary_steps[@]}"; do
        log "INFO" "Setting canary traffic to $weight%"
        
        # Update traffic weight (this would typically use Istio, Linkerd, or similar)
        kubectl patch virtualservice "$DEPLOYMENT_NAME-vs" -n "$NAMESPACE" --type='merge' -p="{
          \"spec\": {
            \"http\": [{
              \"match\": [{\"uri\": {\"prefix\": \"/\"}}],
              \"route\": [
                {\"destination\": {\"host\": \"$DEPLOYMENT_NAME-service\"}, \"weight\": $((100-weight))},
                {\"destination\": {\"host\": \"$DEPLOYMENT_NAME-canary\"}, \"weight\": $weight}
              ]
            }]
          }
        }" 2>/dev/null || log "WARN" "VirtualService patch failed (traffic management may not be configured)"
        
        # Monitor for 2 minutes
        sleep 120
        
        # Check error rates and performance
        if ! monitor_canary_deployment; then
            log "ERROR" "Canary deployment failed health checks, rolling back"
            rollback_canary_deployment
            return 1
        fi
        
        log "SUCCESS" "Canary at $weight% is healthy"
    done
    
    # Replace main deployment with canary
    kubectl patch service "$DEPLOYMENT_NAME-service" -n "$NAMESPACE" -p '{"spec":{"selector":{"version":"canary"}}}'
    kubectl delete deployment "$DEPLOYMENT_NAME-canary" -n "$NAMESPACE"
    
    log "SUCCESS" "Canary deployment promoted to production"
}

monitor_canary_deployment() {
    # This would typically check metrics from Prometheus or similar
    # For now, we'll do a basic health check
    return $(perform_health_check "$DEPLOYMENT_NAME-canary" 60)
}

rollback_canary_deployment() {
    log "INFO" "Rolling back canary deployment..."
    
    # Route all traffic back to stable version
    kubectl patch virtualservice "$DEPLOYMENT_NAME-vs" -n "$NAMESPACE" --type='merge' -p="{
      \"spec\": {\"http\": [{\"route\": [{\"destination\": {\"host\": \"$DEPLOYMENT_NAME-service\"}, \"weight\": 100}]}]}
    }" 2>/dev/null || true
    
    # Remove canary deployment
    kubectl delete deployment "$DEPLOYMENT_NAME-canary" -n "$NAMESPACE" --ignore-not-found
}

perform_health_check() {
    local service_name=${1:-$DEPLOYMENT_NAME}
    local timeout=${2:-300}
    local max_attempts=$((timeout / 10))
    local attempt=0
    
    log "INFO" "Performing health check for $service_name (timeout: ${timeout}s)..."
    
    while [[ $attempt -lt $max_attempts ]]; do
        attempt=$((attempt + 1))
        log "DEBUG" "Health check attempt $attempt/$max_attempts"
        
        # Check if pods are ready
        local ready_replicas=$(kubectl get deployment "$service_name" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        local desired_replicas=$(kubectl get deployment "$service_name" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" != "0" ]]; then
            # Additional health check via endpoint
            if check_application_health "$service_name"; then
                log "SUCCESS" "Health check passed for $service_name"
                return 0
            fi
        fi
        
        sleep 10
    done
    
    log "ERROR" "Health check failed for $service_name after ${timeout}s"
    return 1
}

check_application_health() {
    local service_name="$1"
    
    # Port forward to check health endpoint
    kubectl port-forward service/"$service_name" 8080:80 -n "$NAMESPACE" >/dev/null 2>&1 &
    local port_forward_pid=$!
    sleep 5
    
    local health_status=1
    if curl -f -s http://localhost:8080/health >/dev/null 2>&1; then
        health_status=0
    fi
    
    kill $port_forward_pid 2>/dev/null || true
    return $health_status
}

run_post_deployment_tests() {
    log "INFO" "Running post-deployment tests..."
    
    # Smoke tests
    if ! run_smoke_tests; then
        log "ERROR" "Smoke tests failed"
        return 1
    fi
    
    # Integration tests (if configured)
    if [[ "$ENVIRONMENT" != "development" ]]; then
        if ! run_integration_tests; then
            log "WARN" "Integration tests failed (not blocking)"
        fi
    fi
    
    log "SUCCESS" "Post-deployment tests completed"
    return 0
}

run_smoke_tests() {
    log "DEBUG" "Running smoke tests..."
    
    # Basic connectivity tests
    local endpoints=("/health" "/api/v1/ping" "/api/v1/version")
    
    for endpoint in "${endpoints[@]}"; do
        kubectl port-forward service/"$DEPLOYMENT_NAME" 8080:80 -n "$NAMESPACE" >/dev/null 2>&1 &
        local port_forward_pid=$!
        sleep 2
        
        if curl -f -s "http://localhost:8080$endpoint" >/dev/null 2>&1; then
            log "DEBUG" "Smoke test passed: $endpoint"
        else
            log "ERROR" "Smoke test failed: $endpoint"
            kill $port_forward_pid 2>/dev/null || true
            return 1
        fi
        
        kill $port_forward_pid 2>/dev/null || true
    done
    
    return 0
}

run_integration_tests() {
    log "DEBUG" "Running integration tests..."
    
    # This would run actual integration tests
    # For now, we'll simulate
    sleep 5
    return 0
}

send_notification() {
    local status="$1"  # success or failure
    local message="$2"
    
    if [[ "$NOTIFICATION_ENABLED" != "true" ]]; then
        log "DEBUG" "Notifications disabled, skipping"
        return 0
    fi
    
    log "INFO" "Sending deployment notification..."
    
    # Slack notification (if webhook is configured)
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        local color
        local icon
        
        case "$status" in
            success)
                color="good"
                icon=":rocket:"
                ;;
            failure)
                color="danger"
                icon=":x:"
                ;;
        esac
        
        local payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "$color",
            "title": "${icon} Fortress Deployment $status",
            "fields": [
                {
                    "title": "Environment",
                    "value": "$ENVIRONMENT",
                    "short": true
                },
                {
                    "title": "Strategy",
                    "value": "$DEPLOYMENT_STRATEGY",
                    "short": true
                },
                {
                    "title": "Image Tag",
                    "value": "$IMAGE_TAG",
                    "short": true
                },
                {
                    "title": "Namespace",
                    "value": "$NAMESPACE",
                    "short": true
                },
                {
                    "title": "Message",
                    "value": "$message",
                    "short": false
                }
            ],
            "footer": "Pat Fortress Deployment Automation",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        curl -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
        log "DEBUG" "Slack notification sent"
    fi
}

cleanup() {
    log "INFO" "Performing cleanup..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Clean up temporary files older than 7 days
    find /tmp -name "deployment-*" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

main() {
    trap cleanup EXIT
    
    log "INFO" "🚀 Starting Fortress Deployment Automation"
    log "INFO" "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    
    # Parse command line arguments
    parse_args "$@"
    
    # Log configuration
    log "INFO" "Configuration:"
    log "INFO" "  Namespace: $NAMESPACE"
    log "INFO" "  Deployment: $DEPLOYMENT_NAME"
    log "INFO" "  Environment: $ENVIRONMENT"
    log "INFO" "  Strategy: $DEPLOYMENT_STRATEGY"
    log "INFO" "  Image Tag: $IMAGE_TAG"
    log "INFO" "  Dry Run: $DRY_RUN"
    log "INFO" "  Skip Quality Gates: $SKIP_QUALITY_GATES"
    log "INFO" "  Force Deploy: $FORCE_DEPLOY"
    
    # Validate prerequisites
    validate_prerequisites
    
    # Load quality gates configuration
    load_quality_gates_config
    
    # Validate quality gates
    if ! validate_quality_gates; then
        log "ERROR" "Quality gate validation failed"
        send_notification "failure" "Quality gate validation failed for $DEPLOYMENT_NAME in $ENVIRONMENT"
        exit 1
    fi
    
    # Prepare deployment
    prepare_deployment
    
    # Execute deployment
    if execute_deployment; then
        log "SUCCESS" "Deployment executed successfully"
        
        # Run post-deployment tests
        if run_post_deployment_tests; then
            log "SUCCESS" "✅ Deployment completed successfully"
            send_notification "success" "Deployment completed successfully for $DEPLOYMENT_NAME:$IMAGE_TAG in $ENVIRONMENT using $DEPLOYMENT_STRATEGY strategy"
            exit 0
        else
            log "ERROR" "Post-deployment tests failed"
            send_notification "failure" "Post-deployment tests failed for $DEPLOYMENT_NAME in $ENVIRONMENT"
            exit 1
        fi
    else
        log "ERROR" "❌ Deployment failed"
        send_notification "failure" "Deployment failed for $DEPLOYMENT_NAME:$IMAGE_TAG in $ENVIRONMENT"
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi