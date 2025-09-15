#!/bin/bash
# 🔄 Fortress Rollback Automation Script
# Intelligent rollback automation for Pat Fortress deployments

set -euo pipefail

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${PROJECT_ROOT}/.github/quality-gates-config.yml"

# Default values
NAMESPACE=""
DEPLOYMENT_NAME=""
ENVIRONMENT=""
ROLLBACK_TYPE="auto"
PRESERVE_LOGS="true"
NOTIFICATION_ENABLED="true"
DRY_RUN="false"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===== LOGGING =====
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    
    case "$level" in
        INFO)
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" | tee -a /tmp/rollback.log
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" | tee -a /tmp/rollback.log
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a /tmp/rollback.log
            ;;
        DEBUG)
            if [[ "${DEBUG:-}" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" | tee -a /tmp/rollback.log
            fi
            ;;
    esac
}

# ===== UTILITY FUNCTIONS =====
usage() {
    cat << EOF
🔄 Fortress Rollback Automation Script

Usage: $0 [OPTIONS]

OPTIONS:
    -n, --namespace NAMESPACE       Kubernetes namespace
    -d, --deployment DEPLOYMENT     Deployment name
    -e, --environment ENV           Environment (dev/staging/production)
    -t, --type TYPE                 Rollback type (auto/manual)
    -p, --preserve-logs BOOL        Preserve logs during rollback (true/false)
    --dry-run                       Perform dry run without actual rollback
    --no-notifications              Disable notifications
    -h, --help                      Show this help message

EXAMPLES:
    $0 -n pat-production -d pat-app -e production -t auto
    $0 --namespace pat-staging --deployment pat-service --environment staging --dry-run
    $0 -n pat-dev -d pat-app -e development --type manual --no-notifications

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
            -t|--type)
                ROLLBACK_TYPE="$2"
                shift 2
                ;;
            -p|--preserve-logs)
                PRESERVE_LOGS="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
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
    if [[ -z "$NAMESPACE" ]] || [[ -z "$DEPLOYMENT_NAME" ]] || [[ -z "$ENVIRONMENT" ]]; then
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
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log "ERROR" "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log "ERROR" "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Verify cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log "ERROR" "Unable to connect to Kubernetes cluster"
        exit 1
    fi
    
    # Verify namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log "ERROR" "Namespace '$NAMESPACE' does not exist"
        exit 1
    fi
    
    # Verify deployment exists
    if ! kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" &> /dev/null; then
        log "ERROR" "Deployment '$DEPLOYMENT_NAME' does not exist in namespace '$NAMESPACE'"
        exit 1
    fi
    
    log "INFO" "Prerequisites validation completed successfully"
}

get_current_deployment_info() {
    log "INFO" "Gathering current deployment information..."
    
    # Get current deployment details
    CURRENT_IMAGE=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
    CURRENT_REPLICAS=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    CURRENT_REVISION=$(kubectl rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --revision=0 | tail -1 | awk '{print $1}')
    
    log "INFO" "Current deployment details:"
    log "INFO" "  Image: $CURRENT_IMAGE"
    log "INFO" "  Replicas: $CURRENT_REPLICAS"
    log "INFO" "  Revision: $CURRENT_REVISION"
    
    # Get rollout history
    log "DEBUG" "Rollout history:"
    kubectl rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" | tee -a /tmp/rollback.log
}

check_rollback_eligibility() {
    log "INFO" "Checking rollback eligibility..."
    
    # Check if there's a previous revision to rollback to
    REVISION_COUNT=$(kubectl rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" | grep -c "^[0-9]" || echo "0")
    
    if [[ $REVISION_COUNT -lt 2 ]]; then
        log "ERROR" "No previous revision available for rollback"
        exit 1
    fi
    
    # Get previous revision info
    PREVIOUS_REVISION=$((CURRENT_REVISION - 1))
    if [[ $PREVIOUS_REVISION -lt 1 ]]; then
        PREVIOUS_REVISION=$(kubectl rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" | grep -v "^REVISION" | tail -2 | head -1 | awk '{print $1}')
    fi
    
    log "INFO" "Previous revision available: $PREVIOUS_REVISION"
    
    # Check rollback policy for environment
    case "$ENVIRONMENT" in
        production)
            if [[ "$ROLLBACK_TYPE" == "auto" ]] && [[ "${REQUIRE_APPROVAL:-true}" == "true" ]]; then
                log "ERROR" "Automatic rollback requires approval in production environment"
                return 1
            fi
            ;;
    esac
    
    log "INFO" "Rollback eligibility check passed"
    return 0
}

preserve_deployment_logs() {
    if [[ "$PRESERVE_LOGS" != "true" ]]; then
        log "INFO" "Log preservation disabled, skipping"
        return 0
    fi
    
    log "INFO" "Preserving deployment logs..."
    
    local log_dir="/tmp/rollback-logs-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$log_dir"
    
    # Get pod logs before rollback
    log "DEBUG" "Collecting pod logs..."
    local pods=$(kubectl get pods -n "$NAMESPACE" -l app="$DEPLOYMENT_NAME" -o name)
    
    for pod in $pods; do
        local pod_name=$(echo "$pod" | cut -d'/' -f2)
        log "DEBUG" "Collecting logs for pod: $pod_name"
        
        # Current logs
        kubectl logs "$pod" -n "$NAMESPACE" --previous=false > "$log_dir/${pod_name}-current.log" 2>/dev/null || true
        
        # Previous logs
        kubectl logs "$pod" -n "$NAMESPACE" --previous=true > "$log_dir/${pod_name}-previous.log" 2>/dev/null || true
    done
    
    # Get deployment events
    kubectl get events -n "$NAMESPACE" --field-selector involvedObject.name="$DEPLOYMENT_NAME" > "$log_dir/deployment-events.log" 2>/dev/null || true
    
    # Get deployment description
    kubectl describe deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" > "$log_dir/deployment-description.log" 2>/dev/null || true
    
    log "INFO" "Logs preserved in: $log_dir"
    echo "LOG_DIR=$log_dir" >> /tmp/rollback.log
}

perform_health_check() {
    local timeout=${1:-300}  # Default 5 minutes
    local max_attempts=$((timeout / 10))
    local attempt=0
    
    log "INFO" "Performing health check (timeout: ${timeout}s)..."
    
    while [[ $attempt -lt $max_attempts ]]; do
        attempt=$((attempt + 1))
        log "DEBUG" "Health check attempt $attempt/$max_attempts"
        
        # Check deployment status
        local ready_replicas=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        local desired_replicas=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" != "0" ]]; then
            # Additional health check via service endpoint if available
            local service_ip=$(kubectl get service "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
            
            if [[ -n "$service_ip" ]]; then
                # Port forward for health check
                kubectl port-forward service/"$DEPLOYMENT_NAME" 8080:80 -n "$NAMESPACE" >/dev/null 2>&1 &
                local port_forward_pid=$!
                sleep 5
                
                if curl -f -s http://localhost:8080/health >/dev/null 2>&1; then
                    kill $port_forward_pid 2>/dev/null || true
                    log "INFO" "Health check passed - application is healthy"
                    return 0
                fi
                
                kill $port_forward_pid 2>/dev/null || true
            else
                log "INFO" "Health check passed - deployment is ready"
                return 0
            fi
        fi
        
        sleep 10
    done
    
    log "ERROR" "Health check failed after ${timeout}s"
    return 1
}

execute_rollback() {
    log "INFO" "Executing rollback..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would rollback deployment '$DEPLOYMENT_NAME' in namespace '$NAMESPACE'"
        log "INFO" "DRY RUN: Target revision: $PREVIOUS_REVISION"
        return 0
    fi
    
    # Preserve logs before rollback
    preserve_deployment_logs
    
    # Record rollback start time
    local rollback_start=$(date +%s)
    
    # Perform the rollback
    log "INFO" "Rolling back deployment to revision $PREVIOUS_REVISION..."
    
    if kubectl rollout undo deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --to-revision="$PREVIOUS_REVISION"; then
        log "INFO" "Rollback command executed successfully"
    else
        log "ERROR" "Rollback command failed"
        return 1
    fi
    
    # Wait for rollback to complete
    log "INFO" "Waiting for rollback to complete..."
    if kubectl rollout status deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --timeout=600s; then
        log "INFO" "Rollback deployment completed"
    else
        log "ERROR" "Rollback deployment timed out or failed"
        return 1
    fi
    
    # Perform health check
    if perform_health_check 300; then
        local rollback_end=$(date +%s)
        local rollback_duration=$((rollback_end - rollback_start))
        log "INFO" "Rollback completed successfully in ${rollback_duration}s"
        
        # Get new deployment info
        local new_image=$(kubectl get deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
        local new_revision=$(kubectl rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --revision=0 | tail -1 | awk '{print $1}')
        
        log "INFO" "Rollback summary:"
        log "INFO" "  Previous Image: $CURRENT_IMAGE"
        log "INFO" "  New Image: $new_image"
        log "INFO" "  Previous Revision: $CURRENT_REVISION"
        log "INFO" "  New Revision: $new_revision"
        log "INFO" "  Duration: ${rollback_duration}s"
        
        return 0
    else
        log "ERROR" "Rollback health check failed"
        return 1
    fi
}

send_notification() {
    local status="$1"  # success or failure
    local message="$2"
    
    if [[ "$NOTIFICATION_ENABLED" != "true" ]]; then
        log "DEBUG" "Notifications disabled, skipping"
        return 0
    fi
    
    log "INFO" "Sending rollback notification..."
    
    # Slack notification (if webhook is configured)
    if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
        local color
        local icon
        
        case "$status" in
            success)
                color="good"
                icon=":white_check_mark:"
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
            "title": "${icon} Fortress Rollback $status",
            "fields": [
                {
                    "title": "Environment",
                    "value": "$ENVIRONMENT",
                    "short": true
                },
                {
                    "title": "Namespace",
                    "value": "$NAMESPACE",
                    "short": true
                },
                {
                    "title": "Deployment",
                    "value": "$DEPLOYMENT_NAME",
                    "short": true
                },
                {
                    "title": "Type",
                    "value": "$ROLLBACK_TYPE",
                    "short": true
                },
                {
                    "title": "Message",
                    "value": "$message",
                    "short": false
                }
            ],
            "footer": "Pat Fortress Rollback Automation",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        curl -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
        log "DEBUG" "Slack notification sent"
    fi
    
    # Log the notification
    log "INFO" "Rollback notification sent: $status - $message"
}

cleanup() {
    log "INFO" "Performing cleanup..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Clean up temporary files older than 7 days
    find /tmp -name "rollback-logs-*" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

main() {
    trap cleanup EXIT
    
    log "INFO" "🔄 Starting Fortress Rollback Automation"
    log "INFO" "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    
    # Parse command line arguments
    parse_args "$@"
    
    # Log configuration
    log "INFO" "Configuration:"
    log "INFO" "  Namespace: $NAMESPACE"
    log "INFO" "  Deployment: $DEPLOYMENT_NAME"
    log "INFO" "  Environment: $ENVIRONMENT"
    log "INFO" "  Rollback Type: $ROLLBACK_TYPE"
    log "INFO" "  Preserve Logs: $PRESERVE_LOGS"
    log "INFO" "  Dry Run: $DRY_RUN"
    log "INFO" "  Notifications: $NOTIFICATION_ENABLED"
    
    # Validate prerequisites
    validate_prerequisites
    
    # Get current deployment info
    get_current_deployment_info
    
    # Check if rollback is possible and allowed
    if ! check_rollback_eligibility; then
        log "ERROR" "Rollback eligibility check failed"
        send_notification "failure" "Rollback eligibility check failed for $DEPLOYMENT_NAME in $ENVIRONMENT"
        exit 1
    fi
    
    # Execute the rollback
    if execute_rollback; then
        log "INFO" "✅ Rollback completed successfully"
        send_notification "success" "Rollback completed successfully for $DEPLOYMENT_NAME in $ENVIRONMENT"
        exit 0
    else
        log "ERROR" "❌ Rollback failed"
        send_notification "failure" "Rollback failed for $DEPLOYMENT_NAME in $ENVIRONMENT"
        exit 1
    fi
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi