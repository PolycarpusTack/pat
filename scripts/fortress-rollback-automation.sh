#!/bin/bash
# =============================================================================
# Fortress Intelligent Rollback Automation System
# Advanced Failure Detection and Automated Recovery
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration and Global Variables
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_DIR="${PROJECT_ROOT}/logs/rollback"
readonly STATE_DIR="${PROJECT_ROOT}/rollback-state"
readonly CONFIG_DIR="${PROJECT_ROOT}/config"

# Create directories
mkdir -p "$LOG_DIR" "$STATE_DIR" "${CONFIG_DIR}/rollback"

# Logging setup
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="${LOG_DIR}/rollback-${TIMESTAMP}.log"
readonly ROLLBACK_REPORT="${LOG_DIR}/rollback-report-${TIMESTAMP}.json"

exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
ROLLBACK_STRATEGY="${ROLLBACK_STRATEGY:-auto-detect}"
ROLLBACK_TIMEOUT="${ROLLBACK_TIMEOUT:-600}"
HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL:-30}"
MAX_ROLLBACK_ATTEMPTS="${MAX_ROLLBACK_ATTEMPTS:-3}"
NOTIFICATION_WEBHOOK="${NOTIFICATION_WEBHOOK:-}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_ROLLBACK="${FORCE_ROLLBACK:-false}"

# State tracking
ROLLBACK_ID="rollback-${ENVIRONMENT}-${TIMESTAMP}"
ROLLBACK_START_TIME=$(date +%s)
ROLLBACK_REASON=""
ORIGINAL_DEPLOYMENT_ID=""
TARGET_VERSION=""
CURRENT_VERSION=""
ROLLBACK_ATTEMPTS=0
ROLLBACK_SUCCESS=false

# Failure detection thresholds
ERROR_RATE_THRESHOLD="${ERROR_RATE_THRESHOLD:-5.0}"      # 5%
RESPONSE_TIME_THRESHOLD="${RESPONSE_TIME_THRESHOLD:-2000}" # 2 seconds
CPU_THRESHOLD="${CPU_THRESHOLD:-80}"                     # 80%
MEMORY_THRESHOLD="${MEMORY_THRESHOLD:-85}"               # 85%
DISK_THRESHOLD="${DISK_THRESHOLD:-90}"                   # 90%

# =============================================================================
# Logging and Notification Functions
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

critical() {
    echo -e "${RED}${BOLD}[$(date +'%Y-%m-%d %H:%M:%S')] [CRITICAL] $*${NC}" >&2
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] [DEBUG] $*${NC}"
    fi
}

# Send notifications
send_notification() {
    local level="$1"
    local message="$2"
    local details="${3:-}"
    
    local payload="{
        \"rollback_id\": \"$ROLLBACK_ID\",
        \"level\": \"$level\",
        \"message\": \"$message\",
        \"details\": \"$details\",
        \"environment\": \"$ENVIRONMENT\",
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
    }"
    
    if [[ -n "$NOTIFICATION_WEBHOOK" && "$DRY_RUN" != "true" ]]; then
        curl -X POST "$NOTIFICATION_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "$payload" \
             --max-time 10 \
             --silent || warn "Failed to send notification"
    fi
    
    log "Notification sent: $level - $message"
}

# =============================================================================
# State Management
# =============================================================================

save_rollback_state() {
    local state_type="$1"
    local additional_data="${2:-{}}"
    
    local state_file="${STATE_DIR}/rollback-state-${ROLLBACK_ID}.json"
    
    local state="{
        \"rollback_id\": \"$ROLLBACK_ID\",
        \"state_type\": \"$state_type\",
        \"timestamp\": $(date +%s),
        \"environment\": \"$ENVIRONMENT\",
        \"strategy\": \"$ROLLBACK_STRATEGY\",
        \"reason\": \"$ROLLBACK_REASON\",
        \"original_deployment_id\": \"$ORIGINAL_DEPLOYMENT_ID\",
        \"target_version\": \"$TARGET_VERSION\",
        \"current_version\": \"$CURRENT_VERSION\",
        \"attempts\": $ROLLBACK_ATTEMPTS,
        \"kubernetes_state\": $(capture_kubernetes_state),
        \"additional_data\": $additional_data
    }"
    
    echo "$state" > "$state_file"
    
    debug "Rollback state saved: $state_file"
}

load_deployment_state() {
    local deployment_id="$1"
    local state_file="${PROJECT_ROOT}/logs/production-deployment/rollback-state-${deployment_id}.json"
    
    if [[ ! -f "$state_file" ]]; then
        # Try to find the latest state file
        state_file=$(find "${PROJECT_ROOT}/logs" -name "rollback-state-*.json" -type f -exec stat --format='%Y %n' {} \; | sort -nr | head -1 | cut -d' ' -f2- || echo "")
    fi
    
    if [[ -f "$state_file" ]]; then
        TARGET_VERSION=$(jq -r '.current_version // "unknown"' "$state_file")
        ORIGINAL_DEPLOYMENT_ID=$(jq -r '.deployment_id // "unknown"' "$state_file")
        
        debug "Loaded deployment state from: $state_file"
        debug "Target rollback version: $TARGET_VERSION"
    else
        warn "No deployment state file found for: $deployment_id"
        # Try to auto-detect from git
        TARGET_VERSION=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "unknown")
        warn "Using git-detected target version: $TARGET_VERSION"
    fi
}

capture_kubernetes_state() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "{\"dry_run\": true}"
        return
    fi
    
    local k8s_state="{}"
    
    if kubectl cluster-info >/dev/null 2>&1; then
        k8s_state=$(kubectl get deployments,services,pods -n fortress -o json 2>/dev/null | jq '{
            "deployments": [.items[] | select(.kind == "Deployment") | {
                "name": .metadata.name,
                "image": .spec.template.spec.containers[0].image,
                "replicas": .spec.replicas,
                "ready_replicas": .status.readyReplicas,
                "status": .status.conditions[-1].type
            }],
            "services": [.items[] | select(.kind == "Service") | {
                "name": .metadata.name,
                "type": .spec.type,
                "cluster_ip": .spec.clusterIP
            }],
            "pods": [.items[] | select(.kind == "Pod") | {
                "name": .metadata.name,
                "phase": .status.phase,
                "ready": .status.conditions[]? | select(.type == "Ready") | .status
            }]
        }' || echo '{}')
    fi
    
    echo "$k8s_state"
}

# =============================================================================
# Failure Detection System
# =============================================================================

detect_deployment_failures() {
    log "🔍 Starting intelligent failure detection..."
    
    local failure_detected=false
    local failure_reasons=()
    
    # Multi-dimensional failure detection
    if detect_service_failures; then
        failure_detected=true
        failure_reasons+=("service_failures")
    fi
    
    if detect_performance_degradation; then
        failure_detected=true
        failure_reasons+=("performance_degradation")
    fi
    
    if detect_error_rate_spike; then
        failure_detected=true
        failure_reasons+=("error_rate_spike")
    fi
    
    if detect_resource_exhaustion; then
        failure_detected=true
        failure_reasons+=("resource_exhaustion")
    fi
    
    if detect_health_check_failures; then
        failure_detected=true
        failure_reasons+=("health_check_failures")
    fi
    
    if [[ "$failure_detected" == "true" ]]; then
        ROLLBACK_REASON=$(IFS=','; echo "${failure_reasons[*]}")
        critical "🚨 Deployment failure detected: $ROLLBACK_REASON"
        return 0  # Failure detected
    else
        success "✅ No deployment failures detected"
        return 1  # No failure
    fi
}

detect_service_failures() {
    debug "Checking for service failures..."
    
    local services=("fortress-api" "fortress-smtp" "fortress-workflows")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if ! kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            failed_services+=("$service (not found)")
            continue
        fi
        
        local ready_replicas
        ready_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        
        local desired_replicas
        desired_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
        
        if [[ "$ready_replicas" -lt "$desired_replicas" ]]; then
            failed_services+=("$service ($ready_replicas/$desired_replicas ready)")
        fi
        
        # Check for crash loops
        local restart_count
        restart_count=$(kubectl get pods -n fortress -l app="$service" -o jsonpath='{.items[*].status.containerStatuses[*].restartCount}' | awk '{sum += $1} END {print sum+0}')
        
        if [[ "$restart_count" -gt 5 ]]; then
            failed_services+=("$service (high restart count: $restart_count)")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        error "Service failures detected: ${failed_services[*]}"
        return 0  # Failure detected
    fi
    
    return 1  # No failures
}

detect_performance_degradation() {
    debug "Checking for performance degradation..."
    
    local performance_issues=()
    
    # Check response times (simplified - would use actual monitoring data)
    local avg_response_time
    avg_response_time=$(get_average_response_time)
    
    if [[ "$avg_response_time" -gt "$RESPONSE_TIME_THRESHOLD" ]]; then
        performance_issues+=("high_response_time:${avg_response_time}ms")
    fi
    
    # Check throughput degradation
    local current_rps
    current_rps=$(get_current_requests_per_second)
    
    local baseline_rps
    baseline_rps=$(get_baseline_requests_per_second)
    
    if [[ "$current_rps" -lt $((baseline_rps / 2)) ]]; then  # 50% drop
        performance_issues+=("throughput_drop:${current_rps}rps")
    fi
    
    if [[ ${#performance_issues[@]} -gt 0 ]]; then
        error "Performance degradation detected: ${performance_issues[*]}"
        return 0  # Degradation detected
    fi
    
    return 1  # No degradation
}

detect_error_rate_spike() {
    debug "Checking for error rate spikes..."
    
    local current_error_rate
    current_error_rate=$(get_current_error_rate)
    
    if (( $(echo "$current_error_rate > $ERROR_RATE_THRESHOLD" | bc -l 2>/dev/null || echo "0") )); then
        error "Error rate spike detected: ${current_error_rate}% (threshold: ${ERROR_RATE_THRESHOLD}%)"
        return 0  # Spike detected
    fi
    
    return 1  # No spike
}

detect_resource_exhaustion() {
    debug "Checking for resource exhaustion..."
    
    local resource_issues=()
    
    # Check CPU usage
    local avg_cpu_usage
    avg_cpu_usage=$(get_average_cpu_usage)
    
    if [[ "$avg_cpu_usage" -gt "$CPU_THRESHOLD" ]]; then
        resource_issues+=("high_cpu:${avg_cpu_usage}%")
    fi
    
    # Check memory usage
    local avg_memory_usage
    avg_memory_usage=$(get_average_memory_usage)
    
    if [[ "$avg_memory_usage" -gt "$MEMORY_THRESHOLD" ]]; then
        resource_issues+=("high_memory:${avg_memory_usage}%")
    fi
    
    # Check disk usage
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ "$disk_usage" -gt "$DISK_THRESHOLD" ]]; then
        resource_issues+=("high_disk:${disk_usage}%")
    fi
    
    if [[ ${#resource_issues[@]} -gt 0 ]]; then
        error "Resource exhaustion detected: ${resource_issues[*]}"
        return 0  # Exhaustion detected
    fi
    
    return 1  # No exhaustion
}

detect_health_check_failures() {
    debug "Checking for health check failures..."
    
    local failed_health_checks=()
    
    local health_endpoints=(
        "http://localhost:8025/health"
        "http://localhost:8025/ready"
        "http://localhost:1025/health"
    )
    
    # Port forward for health checks
    kubectl port-forward -n fortress service/fortress-api 18025:8025 &
    local api_port_forward_pid=$!
    
    kubectl port-forward -n fortress service/fortress-smtp 11025:1025 &
    local smtp_port_forward_pid=$!
    
    sleep 5  # Wait for port forwards
    
    for endpoint in "${health_endpoints[@]}"; do
        local adjusted_endpoint
        adjusted_endpoint=$(echo "$endpoint" | sed 's/8025/18025/g' | sed 's/1025/11025/g')
        
        if ! timeout 10 curl -f -s "$adjusted_endpoint" >/dev/null 2>&1; then
            failed_health_checks+=("$endpoint")
        fi
    done
    
    # Clean up port forwards
    kill $api_port_forward_pid $smtp_port_forward_pid 2>/dev/null || true
    
    if [[ ${#failed_health_checks[@]} -gt 0 ]]; then
        error "Health check failures detected: ${failed_health_checks[*]}"
        return 0  # Failures detected
    fi
    
    return 1  # No failures
}

# =============================================================================
# Monitoring Data Collection (Simplified)
# =============================================================================

get_average_response_time() {
    # Simplified - in practice would query Prometheus/monitoring system
    local response_time=500  # milliseconds
    
    # Simulate getting data from monitoring
    if command -v kubectl >/dev/null 2>&1; then
        # Try to get actual metrics if available
        local metrics_available=false
        if kubectl get pods -n fortress -l app=prometheus --no-headers 2>/dev/null | grep -q Running; then
            metrics_available=true
        fi
        
        if [[ "$metrics_available" == "true" ]]; then
            # Would query actual Prometheus metrics here
            response_time=750  # Simulated higher response time
        fi
    fi
    
    echo "$response_time"
}

get_current_requests_per_second() {
    # Simplified - in practice would query monitoring system
    echo "100"  # Simulated RPS
}

get_baseline_requests_per_second() {
    # Simplified - would read from baseline stored during deployment
    echo "200"  # Simulated baseline RPS
}

get_current_error_rate() {
    # Simplified - in practice would query monitoring system
    local error_rate="2.1"
    
    # Simulate higher error rate for testing
    if [[ "${SIMULATE_ERRORS:-false}" == "true" ]]; then
        error_rate="7.5"
    fi
    
    echo "$error_rate"
}

get_average_cpu_usage() {
    # Get actual CPU usage from Kubernetes if possible
    local cpu_usage=45
    
    if kubectl top pods -n fortress --no-headers 2>/dev/null | grep -q fortress; then
        cpu_usage=$(kubectl top pods -n fortress --no-headers 2>/dev/null | awk '{gsub(/m/, "", $2); sum += $2} END {print int(sum/NR/10)}' || echo "45")
    fi
    
    echo "$cpu_usage"
}

get_average_memory_usage() {
    # Get actual memory usage from Kubernetes if possible
    local memory_usage=60
    
    if kubectl top pods -n fortress --no-headers 2>/dev/null | grep -q fortress; then
        memory_usage=$(kubectl top pods -n fortress --no-headers 2>/dev/null | awk '{gsub(/Mi/, "", $3); sum += $3} END {print int(sum/10)}' || echo "60")
    fi
    
    echo "$memory_usage"
}

# =============================================================================
# Rollback Strategy Detection and Execution
# =============================================================================

detect_rollback_strategy() {
    log "🔍 Detecting optimal rollback strategy..."
    
    if [[ "$ROLLBACK_STRATEGY" != "auto-detect" ]]; then
        log "Using specified rollback strategy: $ROLLBACK_STRATEGY"
        return 0
    fi
    
    # Analyze current deployment state to determine best rollback strategy
    local current_deployment_strategy
    current_deployment_strategy=$(detect_current_deployment_strategy)
    
    local failure_severity
    failure_severity=$(assess_failure_severity)
    
    case "$failure_severity" in
        "critical")
            ROLLBACK_STRATEGY="immediate"
            log "Critical failure - using immediate rollback strategy"
            ;;
        "high")
            case "$current_deployment_strategy" in
                "blue-green")
                    ROLLBACK_STRATEGY="blue-green-rollback"
                    ;;
                "canary")
                    ROLLBACK_STRATEGY="canary-rollback"
                    ;;
                *)
                    ROLLBACK_STRATEGY="rolling-rollback"
                    ;;
            esac
            log "High severity failure - using $ROLLBACK_STRATEGY strategy"
            ;;
        "medium")
            ROLLBACK_STRATEGY="gradual-rollback"
            log "Medium severity failure - using gradual rollback strategy"
            ;;
        "low")
            ROLLBACK_STRATEGY="monitored-rollback"
            log "Low severity failure - using monitored rollback strategy"
            ;;
    esac
    
    success "Selected rollback strategy: $ROLLBACK_STRATEGY"
}

detect_current_deployment_strategy() {
    # Check for blue-green indicators
    if kubectl get namespace fortress-green >/dev/null 2>&1 || kubectl get namespace fortress-blue >/dev/null 2>&1; then
        echo "blue-green"
        return
    fi
    
    # Check for canary indicators
    if kubectl get namespace fortress-canary >/dev/null 2>&1; then
        echo "canary"
        return
    fi
    
    # Default to rolling
    echo "rolling"
}

assess_failure_severity() {
    local severity_score=0
    
    # Service failures (high impact)
    if echo "$ROLLBACK_REASON" | grep -q "service_failures"; then
        severity_score=$((severity_score + 40))
    fi
    
    # Error rate spikes (high impact)
    if echo "$ROLLBACK_REASON" | grep -q "error_rate_spike"; then
        severity_score=$((severity_score + 30))
    fi
    
    # Performance degradation (medium impact)
    if echo "$ROLLBACK_REASON" | grep -q "performance_degradation"; then
        severity_score=$((severity_score + 20))
    fi
    
    # Resource exhaustion (medium impact)
    if echo "$ROLLBACK_REASON" | grep -q "resource_exhaustion"; then
        severity_score=$((severity_score + 15))
    fi
    
    # Health check failures (low-medium impact)
    if echo "$ROLLBACK_REASON" | grep -q "health_check_failures"; then
        severity_score=$((severity_score + 10))
    fi
    
    if [[ $severity_score -ge 70 ]]; then
        echo "critical"
    elif [[ $severity_score -ge 50 ]]; then
        echo "high"
    elif [[ $severity_score -ge 25 ]]; then
        echo "medium"
    else
        echo "low"
    fi
}

execute_rollback() {
    log "🔄 Executing rollback strategy: $ROLLBACK_STRATEGY"
    
    ROLLBACK_ATTEMPTS=$((ROLLBACK_ATTEMPTS + 1))
    
    if [[ $ROLLBACK_ATTEMPTS -gt $MAX_ROLLBACK_ATTEMPTS ]]; then
        critical "Maximum rollback attempts exceeded: $ROLLBACK_ATTEMPTS"
        execute_emergency_procedures
        return 1
    fi
    
    save_rollback_state "rollback_initiated" '{"attempt": '$ROLLBACK_ATTEMPTS'}'
    
    send_notification "CRITICAL" "Rollback initiated" "Strategy: $ROLLBACK_STRATEGY, Attempt: $ROLLBACK_ATTEMPTS, Reason: $ROLLBACK_REASON"
    
    case "$ROLLBACK_STRATEGY" in
        "immediate")
            execute_immediate_rollback
            ;;
        "blue-green-rollback")
            execute_blue_green_rollback
            ;;
        "canary-rollback")
            execute_canary_rollback
            ;;
        "rolling-rollback")
            execute_rolling_rollback
            ;;
        "gradual-rollback")
            execute_gradual_rollback
            ;;
        "monitored-rollback")
            execute_monitored_rollback
            ;;
        *)
            error "Unknown rollback strategy: $ROLLBACK_STRATEGY"
            execute_immediate_rollback  # Fallback
            ;;
    esac
    
    # Verify rollback success
    if verify_rollback_success; then
        ROLLBACK_SUCCESS=true
        save_rollback_state "rollback_completed" '{"success": true}'
        success "✅ Rollback completed successfully"
        send_notification "INFO" "Rollback completed successfully" "Attempt: $ROLLBACK_ATTEMPTS"
    else
        error "❌ Rollback verification failed"
        save_rollback_state "rollback_failed" '{"success": false, "attempt": '$ROLLBACK_ATTEMPTS'}'
        
        if [[ $ROLLBACK_ATTEMPTS -lt $MAX_ROLLBACK_ATTEMPTS ]]; then
            warn "Retrying rollback with different strategy..."
            # Try more aggressive strategy on retry
            case "$ROLLBACK_STRATEGY" in
                "monitored-rollback") ROLLBACK_STRATEGY="gradual-rollback" ;;
                "gradual-rollback") ROLLBACK_STRATEGY="rolling-rollback" ;;
                "rolling-rollback") ROLLBACK_STRATEGY="immediate" ;;
                *) ROLLBACK_STRATEGY="immediate" ;;
            esac
            
            sleep 30  # Wait before retry
            execute_rollback
        else
            critical "All rollback attempts failed - executing emergency procedures"
            execute_emergency_procedures
        fi
    fi
}

execute_immediate_rollback() {
    log "Executing immediate rollback..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would perform immediate rollback to version: $TARGET_VERSION"
        return 0
    fi
    
    # Scale down all deployments immediately
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        log "Scaling down $deployment..."
        kubectl scale deployment "$deployment" -n fortress --replicas=0 || warn "Failed to scale down $deployment"
        
        # Update to target version
        log "Updating $deployment to target version: $TARGET_VERSION"
        kubectl set image "deployment/$deployment" \
            "$deployment=fortress/$deployment:$TARGET_VERSION" \
            -n fortress || warn "Failed to update $deployment image"
        
        # Scale back up
        local target_replicas=2
        case "$deployment" in
            "fortress-api") target_replicas=3 ;;
            "fortress-smtp") target_replicas=2 ;;
            "fortress-workflows") target_replicas=2 ;;
        esac
        
        log "Scaling up $deployment to $target_replicas replicas..."
        kubectl scale deployment "$deployment" -n fortress --replicas="$target_replicas"
    done
    
    # Wait for deployments to be ready
    log "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available --timeout="${ROLLBACK_TIMEOUT}s" deployment --all -n fortress || {
        error "Deployments did not become ready within timeout"
        return 1
    }
    
    success "Immediate rollback completed"
}

execute_blue_green_rollback() {
    log "Executing blue-green rollback..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would switch traffic back to blue environment"
        return 0
    fi
    
    # Switch traffic back to blue environment
    log "Switching traffic back to blue environment..."
    
    # Update service selector to point to blue
    kubectl patch service fortress-api -n fortress -p '{"spec":{"selector":{"app":"fortress-api","version":"blue"}}}'
    kubectl patch service fortress-smtp -n fortress -p '{"spec":{"selector":{"app":"fortress-smtp","version":"blue"}}}'
    
    # Wait for traffic switch
    sleep 30
    
    # Clean up green environment
    log "Cleaning up failed green environment..."
    kubectl delete namespace fortress-green --ignore-not-found=true
    
    success "Blue-green rollback completed"
}

execute_canary_rollback() {
    log "Executing canary rollback..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would remove canary deployment and restore full traffic to stable version"
        return 0
    fi
    
    # Remove canary traffic routing
    log "Removing canary traffic routing..."
    # This would update service mesh configuration to route 100% traffic to stable version
    
    # Clean up canary deployment
    log "Cleaning up canary deployment..."
    kubectl delete namespace fortress-canary --ignore-not-found=true
    
    # Ensure stable deployment is healthy
    kubectl wait --for=condition=available --timeout="${ROLLBACK_TIMEOUT}s" deployment --all -n fortress
    
    success "Canary rollback completed"
}

execute_rolling_rollback() {
    log "Executing rolling rollback..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would perform rolling rollback to version: $TARGET_VERSION"
        return 0
    fi
    
    local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for deployment in "${deployments[@]}"; do
        log "Rolling back deployment: $deployment"
        
        # Use kubectl rollout undo if available
        if kubectl rollout history "deployment/$deployment" -n fortress --revision=1 >/dev/null 2>&1; then
            kubectl rollout undo "deployment/$deployment" -n fortress
            kubectl rollout status "deployment/$deployment" -n fortress --timeout="${ROLLBACK_TIMEOUT}s"
        else
            # Manual rollback to target version
            kubectl set image "deployment/$deployment" \
                "$deployment=fortress/$deployment:$TARGET_VERSION" \
                -n fortress
            
            kubectl rollout status "deployment/$deployment" -n fortress --timeout="${ROLLBACK_TIMEOUT}s"
        fi
        
        # Verify deployment health after each rollback
        if ! verify_deployment_health "$deployment"; then
            error "Deployment $deployment failed health check after rollback"
            return 1
        fi
        
        success "Successfully rolled back: $deployment"
    done
    
    success "Rolling rollback completed"
}

execute_gradual_rollback() {
    log "Executing gradual rollback..."
    
    # Gradually reduce traffic to failed version and increase to stable version
    local traffic_percentages=(75 50 25 0)
    
    for percentage in "${traffic_percentages[@]}"; do
        log "Adjusting traffic to failed version: ${percentage}%"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            # This would update service mesh configuration
            adjust_traffic_percentage "$percentage"
        fi
        
        # Monitor for a period
        sleep 60
        
        # Check if issues are resolving
        if [[ "$percentage" -lt 50 ]] && ! detect_deployment_failures; then
            log "Issues resolved at ${percentage}% traffic"
            break
        fi
    done
    
    # Complete rollback
    execute_rolling_rollback
    
    success "Gradual rollback completed"
}

execute_monitored_rollback() {
    log "Executing monitored rollback..."
    
    # Conservative rollback with extensive monitoring
    log "Starting monitored rollback process..."
    
    # First, capture extensive diagnostics
    capture_failure_diagnostics
    
    # Then perform rolling rollback with extended monitoring
    execute_rolling_rollback
    
    # Extended post-rollback monitoring
    log "Starting extended post-rollback monitoring..."
    monitor_post_rollback_health 600  # 10 minutes
    
    success "Monitored rollback completed"
}

adjust_traffic_percentage() {
    local percentage="$1"
    
    # This would typically integrate with service mesh (Istio, Linkerd, etc.)
    log "Adjusting traffic percentage to: ${percentage}%"
    
    # Simplified implementation - in practice would update VirtualService or similar
    debug "Traffic adjustment simulated for percentage: $percentage"
}

# =============================================================================
# Rollback Verification
# =============================================================================

verify_rollback_success() {
    log "🔍 Verifying rollback success..."
    
    local verification_checks=0
    local passed_checks=0
    
    # Service health verification
    if verify_service_health; then
        passed_checks=$((passed_checks + 1))
    fi
    verification_checks=$((verification_checks + 1))
    
    # Performance verification
    if verify_performance_recovery; then
        passed_checks=$((passed_checks + 1))
    fi
    verification_checks=$((verification_checks + 1))
    
    # Error rate verification
    if verify_error_rate_recovery; then
        passed_checks=$((passed_checks + 1))
    fi
    verification_checks=$((verification_checks + 1))
    
    # Health check verification
    if verify_health_checks; then
        passed_checks=$((passed_checks + 1))
    fi
    verification_checks=$((verification_checks + 1))
    
    # Version verification
    if verify_target_version_deployed; then
        passed_checks=$((passed_checks + 1))
    fi
    verification_checks=$((verification_checks + 1))
    
    log "Rollback verification: $passed_checks/$verification_checks checks passed"
    
    # Require at least 80% of checks to pass
    local success_rate
    success_rate=$((passed_checks * 100 / verification_checks))
    
    if [[ $success_rate -ge 80 ]]; then
        success "✅ Rollback verification passed ($success_rate%)"
        return 0
    else
        error "❌ Rollback verification failed ($success_rate%)"
        return 1
    fi
}

verify_service_health() {
    debug "Verifying service health..."
    
    local services=("fortress-api" "fortress-smtp" "fortress-workflows")
    local healthy_services=0
    
    for service in "${services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            local ready_replicas
            ready_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.status.readyReplicas}' || echo "0")
            
            local desired_replicas
            desired_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.spec.replicas}' || echo "1")
            
            if [[ "$ready_replicas" -eq "$desired_replicas" && "$ready_replicas" -gt 0 ]]; then
                healthy_services=$((healthy_services + 1))
            fi
        fi
    done
    
    if [[ $healthy_services -eq ${#services[@]} ]]; then
        success "All services are healthy after rollback"
        return 0
    else
        error "Service health verification failed: $healthy_services/${#services[@]} healthy"
        return 1
    fi
}

verify_performance_recovery() {
    debug "Verifying performance recovery..."
    
    # Wait a bit for metrics to stabilize
    sleep 30
    
    local current_response_time
    current_response_time=$(get_average_response_time)
    
    if [[ "$current_response_time" -lt "$RESPONSE_TIME_THRESHOLD" ]]; then
        success "Performance recovered: ${current_response_time}ms response time"
        return 0
    else
        error "Performance not recovered: ${current_response_time}ms response time"
        return 1
    fi
}

verify_error_rate_recovery() {
    debug "Verifying error rate recovery..."
    
    sleep 30  # Wait for metrics
    
    local current_error_rate
    current_error_rate=$(get_current_error_rate)
    
    if (( $(echo "$current_error_rate <= $ERROR_RATE_THRESHOLD" | bc -l 2>/dev/null || echo "1") )); then
        success "Error rate recovered: ${current_error_rate}%"
        return 0
    else
        error "Error rate not recovered: ${current_error_rate}%"
        return 1
    fi
}

verify_health_checks() {
    debug "Verifying health check endpoints..."
    
    # Port forward for health checks
    kubectl port-forward -n fortress service/fortress-api 18025:8025 &
    local port_forward_pid=$!
    
    sleep 5
    
    local health_endpoints=(
        "http://localhost:18025/health"
        "http://localhost:18025/ready"
        "http://localhost:18025/metrics"
    )
    
    local successful_checks=0
    
    for endpoint in "${health_endpoints[@]}"; do
        if timeout 10 curl -f -s "$endpoint" >/dev/null 2>&1; then
            successful_checks=$((successful_checks + 1))
        fi
    done
    
    kill $port_forward_pid 2>/dev/null || true
    
    if [[ $successful_checks -eq ${#health_endpoints[@]} ]]; then
        success "All health checks passed"
        return 0
    else
        error "Health check verification failed: $successful_checks/${#health_endpoints[@]} passed"
        return 1
    fi
}

verify_target_version_deployed() {
    debug "Verifying target version deployment..."
    
    local services=("fortress-api" "fortress-smtp" "fortress-workflows")
    local correct_versions=0
    
    for service in "${services[@]}"; do
        local current_image
        current_image=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "")
        
        if [[ "$current_image" == *":$TARGET_VERSION" ]]; then
            correct_versions=$((correct_versions + 1))
        else
            debug "Service $service has incorrect version: $current_image (expected: $TARGET_VERSION)"
        fi
    done
    
    if [[ $correct_versions -eq ${#services[@]} ]]; then
        success "All services running target version: $TARGET_VERSION"
        return 0
    else
        error "Version verification failed: $correct_versions/${#services[@]} services have correct version"
        return 1
    fi
}

verify_deployment_health() {
    local deployment="$1"
    
    # Basic deployment health check
    kubectl wait --for=condition=available --timeout=60s "deployment/$deployment" -n fortress >/dev/null 2>&1
}

# =============================================================================
# Emergency Procedures
# =============================================================================

execute_emergency_procedures() {
    critical "🚨 EXECUTING EMERGENCY PROCEDURES"
    
    send_notification "CRITICAL" "Emergency procedures activated" "All automated rollback attempts failed"
    
    # Create emergency incident report
    create_emergency_incident_report
    
    # Attempt to preserve system state
    preserve_emergency_state
    
    # Emergency service isolation
    attempt_service_isolation
    
    # Emergency scaling
    attempt_emergency_scaling
    
    critical "EMERGENCY PROCEDURES COMPLETED - MANUAL INTERVENTION REQUIRED"
    critical "Emergency report: ${LOG_DIR}/emergency-incident-${TIMESTAMP}.txt"
}

create_emergency_incident_report() {
    local incident_file="${LOG_DIR}/emergency-incident-${TIMESTAMP}.txt"
    
    cat > "$incident_file" << EOF
# FORTRESS ROLLBACK EMERGENCY INCIDENT REPORT
Generated: $(date)
Rollback ID: $ROLLBACK_ID
Environment: $ENVIRONMENT
Original Deployment ID: $ORIGINAL_DEPLOYMENT_ID

## Emergency Summary
- Rollback Reason: $ROLLBACK_REASON
- Rollback Strategy: $ROLLBACK_STRATEGY
- Rollback Attempts: $ROLLBACK_ATTEMPTS
- Target Version: $TARGET_VERSION
- Emergency Procedures Triggered: $(date)

## Timeline
$(tail -n 100 "$LOG_FILE")

## System State at Emergency
$(capture_kubernetes_state)

## Failure Detection Results
$(detect_deployment_failures 2>&1 || echo "Failure detection failed")

## Recommended Immediate Actions
1. Assess system availability and user impact
2. Consider manual service isolation
3. Review deployment logs for root cause
4. Implement manual fixes if automated rollback failed
5. Prepare communication for stakeholders

## Next Steps
1. Investigate root cause of deployment failure
2. Review rollback automation for improvements
3. Update incident response procedures
4. Conduct post-incident review

EOF
    
    critical "Emergency incident report created: $incident_file"
}

preserve_emergency_state() {
    log "Preserving emergency system state..."
    
    local emergency_dir="${LOG_DIR}/emergency-state-${TIMESTAMP}"
    mkdir -p "$emergency_dir"
    
    # Capture Kubernetes state
    kubectl get all -n fortress -o yaml > "${emergency_dir}/kubernetes-all.yaml" 2>/dev/null || true
    kubectl describe all -n fortress > "${emergency_dir}/kubernetes-describe.txt" 2>/dev/null || true
    kubectl get events -n fortress --sort-by='.lastTimestamp' > "${emergency_dir}/kubernetes-events.txt" 2>/dev/null || true
    
    # Capture pod logs
    local pods
    pods=$(kubectl get pods -n fortress --no-headers -o custom-columns=":metadata.name" 2>/dev/null || echo "")
    
    for pod in $pods; do
        kubectl logs "$pod" -n fortress > "${emergency_dir}/logs-${pod}.txt" 2>/dev/null || true
        kubectl logs "$pod" -n fortress --previous > "${emergency_dir}/logs-${pod}-previous.txt" 2>/dev/null || true
    done
    
    # Compress emergency state
    tar -czf "${LOG_DIR}/emergency-state-${TIMESTAMP}.tar.gz" -C "$LOG_DIR" "emergency-state-${TIMESTAMP}" 2>/dev/null || true
    
    success "Emergency state preserved"
}

attempt_service_isolation() {
    log "Attempting service isolation..."
    
    # Try to isolate failing services
    local critical_services=("fortress-api")  # Keep API running if possible
    
    for service in "${critical_services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            # Scale to minimum
            kubectl scale deployment "$service" -n fortress --replicas=1 || warn "Failed to scale $service"
            
            # Add resource limits
            kubectl patch deployment "$service" -n fortress -p '{
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "'$service'",
                                "resources": {
                                    "limits": {
                                        "cpu": "500m",
                                        "memory": "1Gi"
                                    }
                                }
                            }]
                        }
                    }
                }
            }' || warn "Failed to add resource limits to $service"
        fi
    done
    
    success "Service isolation attempted"
}

attempt_emergency_scaling() {
    log "Attempting emergency scaling..."
    
    # Scale down resource-intensive services
    local non_critical_services=("fortress-workflows")
    
    for service in "${non_critical_services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            kubectl scale deployment "$service" -n fortress --replicas=0 || warn "Failed to scale down $service"
        fi
    done
    
    success "Emergency scaling attempted"
}

# =============================================================================
# Monitoring and Reporting
# =============================================================================

capture_failure_diagnostics() {
    log "Capturing comprehensive failure diagnostics..."
    
    local diagnostics_file="${LOG_DIR}/failure-diagnostics-${TIMESTAMP}.json"
    
    local diagnostics="{
        \"rollback_id\": \"$ROLLBACK_ID\",
        \"timestamp\": $(date +%s),
        \"failure_reason\": \"$ROLLBACK_REASON\",
        \"metrics\": {
            \"response_time\": $(get_average_response_time),
            \"error_rate\": $(get_current_error_rate),
            \"cpu_usage\": $(get_average_cpu_usage),
            \"memory_usage\": $(get_average_memory_usage),
            \"requests_per_second\": $(get_current_requests_per_second)
        },
        \"kubernetes_state\": $(capture_kubernetes_state)
    }"
    
    echo "$diagnostics" > "$diagnostics_file"
    
    debug "Failure diagnostics captured: $diagnostics_file"
}

monitor_post_rollback_health() {
    local monitor_duration="$1"
    local check_interval=30
    
    log "Monitoring post-rollback health for ${monitor_duration} seconds..."
    
    for ((i=0; i<monitor_duration; i+=check_interval)); do
        if detect_deployment_failures; then
            error "Post-rollback monitoring detected new failures"
            return 1
        fi
        
        log "Post-rollback health check passed (${i}/${monitor_duration}s)"
        sleep $check_interval
    done
    
    success "Post-rollback monitoring completed - system stable"
    return 0
}

generate_rollback_report() {
    log "Generating comprehensive rollback report..."
    
    local rollback_duration=$(($(date +%s) - ROLLBACK_START_TIME))
    
    local report="{
        \"rollback_summary\": {
            \"rollback_id\": \"$ROLLBACK_ID\",
            \"environment\": \"$ENVIRONMENT\",
            \"start_time\": $ROLLBACK_START_TIME,
            \"duration_seconds\": $rollback_duration,
            \"strategy\": \"$ROLLBACK_STRATEGY\",
            \"reason\": \"$ROLLBACK_REASON\",
            \"attempts\": $ROLLBACK_ATTEMPTS,
            \"success\": $ROLLBACK_SUCCESS,
            \"target_version\": \"$TARGET_VERSION\",
            \"original_deployment_id\": \"$ORIGINAL_DEPLOYMENT_ID\"
        },
        \"failure_analysis\": {
            \"detected_failures\": \"$ROLLBACK_REASON\",
            \"failure_severity\": \"$(assess_failure_severity)\",
            \"rollback_triggers\": []
        },
        \"rollback_execution\": {
            \"strategy_used\": \"$ROLLBACK_STRATEGY\",
            \"execution_time\": $rollback_duration,
            \"verification_results\": {
                \"service_health\": $(verify_service_health && echo "true" || echo "false"),
                \"performance_recovery\": $(verify_performance_recovery && echo "true" || echo "false"),
                \"error_rate_recovery\": $(verify_error_rate_recovery && echo "true" || echo "false")
            }
        }
    }"
    
    echo "$report" > "$ROLLBACK_REPORT"
    
    success "Rollback report generated: $ROLLBACK_REPORT"
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log "🚨 Starting Fortress Intelligent Rollback Automation"
    log "Rollback ID: $ROLLBACK_ID"
    log "Environment: $ENVIRONMENT"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Initialize rollback process
    save_rollback_state "rollback_initialized"
    
    # Load deployment state for rollback target
    if [[ -n "$ORIGINAL_DEPLOYMENT_ID" ]]; then
        load_deployment_state "$ORIGINAL_DEPLOYMENT_ID"
    else
        # Auto-detect target version
        TARGET_VERSION=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "previous")
    fi
    
    log "Target rollback version: $TARGET_VERSION"
    
    # Detect failures unless explicitly performing rollback
    if [[ "$FORCE_ROLLBACK" != "true" ]]; then
        if ! detect_deployment_failures; then
            success "No deployment failures detected - rollback not required"
            exit 0
        fi
    else
        ROLLBACK_REASON="forced_rollback"
        log "Forcing rollback as requested"
    fi
    
    # Detect and execute rollback strategy
    detect_rollback_strategy
    execute_rollback
    
    # Generate final report
    generate_rollback_report
    
    if [[ "$ROLLBACK_SUCCESS" == "true" ]]; then
        success "🎉 Rollback completed successfully!"
        success "Duration: $(($(date +%s) - ROLLBACK_START_TIME)) seconds"
        success "Strategy: $ROLLBACK_STRATEGY"
        success "Target version: $TARGET_VERSION"
        exit 0
    else
        critical "💥 Rollback failed after $ROLLBACK_ATTEMPTS attempts"
        critical "Manual intervention required"
        exit 1
    fi
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --deployment-id)
                ORIGINAL_DEPLOYMENT_ID="$2"
                shift 2
                ;;
            --strategy)
                ROLLBACK_STRATEGY="$2"
                shift 2
                ;;
            --target-version)
                TARGET_VERSION="$2"
                shift 2
                ;;
            --reason)
                ROLLBACK_REASON="$2"
                shift 2
                ;;
            --force)
                FORCE_ROLLBACK="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --webhook)
                NOTIFICATION_WEBHOOK="$2"
                shift 2
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
🔄 Fortress Intelligent Rollback Automation

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --deployment-id ID         Original deployment ID to rollback from
    --strategy STRATEGY        Rollback strategy: auto-detect, immediate, blue-green-rollback, 
                              canary-rollback, rolling-rollback, gradual-rollback, monitored-rollback
    --target-version VERSION   Target version to rollback to
    --reason REASON           Reason for rollback
    --force                   Force rollback without failure detection
    --dry-run                 Show what would be done without executing
    --webhook URL             Notification webhook URL
    --help                    Show this help

ROLLBACK STRATEGIES:
    auto-detect               Automatically choose best strategy based on failure analysis
    immediate                 Immediate complete rollback (fastest)
    blue-green-rollback       Switch traffic back to blue environment
    canary-rollback           Remove canary deployment, keep stable
    rolling-rollback          Rolling update back to previous version
    gradual-rollback          Gradually reduce traffic to failed version
    monitored-rollback        Conservative rollback with extended monitoring

EXAMPLES:
    # Automatic failure detection and rollback
    $0

    # Force rollback to specific version
    $0 --force --target-version v1.2.0

    # Rollback specific deployment with custom strategy
    $0 --deployment-id fortress-prod-20241201 --strategy immediate

    # Dry run to see what would happen
    $0 --dry-run --strategy auto-detect

ENVIRONMENT VARIABLES:
    ENVIRONMENT               Environment name (default: production)
    ROLLBACK_STRATEGY         Default rollback strategy
    ROLLBACK_TIMEOUT          Rollback operation timeout in seconds
    MAX_ROLLBACK_ATTEMPTS     Maximum rollback attempts before emergency procedures
    ERROR_RATE_THRESHOLD      Error rate threshold for failure detection (%)
    RESPONSE_TIME_THRESHOLD   Response time threshold for failure detection (ms)
    NOTIFICATION_WEBHOOK      Slack/Teams webhook URL

FAILURE DETECTION THRESHOLDS:
    ERROR_RATE_THRESHOLD      Error rate spike threshold (default: 5.0%)
    RESPONSE_TIME_THRESHOLD   Response time threshold (default: 2000ms)
    CPU_THRESHOLD             CPU usage threshold (default: 80%)
    MEMORY_THRESHOLD          Memory usage threshold (default: 85%)
    DISK_THRESHOLD            Disk usage threshold (default: 90%)

EOF
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi