#!/bin/bash
# =============================================================================
# Pat Fortress - Monitoring Stack Validation Script
# Comprehensive validation of all monitoring components
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROMETHEUS_URL="http://localhost:9090"
GRAFANA_URL="http://localhost:3000"
JAEGER_URL="http://localhost:16686"
LOKI_URL="http://localhost:3100"
ALERTMANAGER_URL="http://localhost:9093"

# Timeout settings
TIMEOUT=30
RETRY_COUNT=5

# =============================================================================
# Utility Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_url_accessible() {
    local url=$1
    local service_name=$2
    
    if curl -sf --max-time $TIMEOUT "$url" >/dev/null 2>&1; then
        log_success "$service_name is accessible at $url"
        return 0
    else
        log_error "$service_name is not accessible at $url"
        return 1
    fi
}

wait_for_service() {
    local url=$1
    local service_name=$2
    local count=0
    
    log_info "Waiting for $service_name to become available..."
    
    while [ $count -lt $RETRY_COUNT ]; do
        if curl -sf --max-time $TIMEOUT "$url" >/dev/null 2>&1; then
            log_success "$service_name is now available"
            return 0
        fi
        
        count=$((count + 1))
        log_info "Attempt $count/$RETRY_COUNT failed, retrying in 10 seconds..."
        sleep 10
    done
    
    log_error "$service_name failed to become available after $RETRY_COUNT attempts"
    return 1
}

# =============================================================================
# Monitoring Stack Validation Functions
# =============================================================================

validate_prometheus() {
    log_info "Validating Prometheus..."
    
    # Check if Prometheus is accessible
    if ! check_url_accessible "$PROMETHEUS_URL" "Prometheus"; then
        return 1
    fi
    
    # Check Prometheus health
    if curl -sf "$PROMETHEUS_URL/-/healthy" >/dev/null 2>&1; then
        log_success "Prometheus health check passed"
    else
        log_error "Prometheus health check failed"
        return 1
    fi
    
    # Check if Prometheus is ready
    if curl -sf "$PROMETHEUS_URL/-/ready" >/dev/null 2>&1; then
        log_success "Prometheus readiness check passed"
    else
        log_error "Prometheus readiness check failed"
        return 1
    fi
    
    # Check targets
    local targets_response
    targets_response=$(curl -sf "$PROMETHEUS_URL/api/v1/targets" 2>/dev/null || echo "")
    
    if [[ -n "$targets_response" ]]; then
        local up_targets
        up_targets=$(echo "$targets_response" | jq -r '.data.activeTargets[] | select(.health == "up") | .scrapeUrl' | wc -l)
        local total_targets
        total_targets=$(echo "$targets_response" | jq -r '.data.activeTargets[].scrapeUrl' | wc -l)
        
        log_info "Prometheus targets: $up_targets/$total_targets are up"
        
        if [ "$up_targets" -eq 0 ]; then
            log_error "No Prometheus targets are up"
            return 1
        fi
    else
        log_warning "Could not retrieve Prometheus targets information"
    fi
    
    # Validate fortress-specific metrics
    local fortress_metrics=("fortress_emails_processed_total" "fortress_http_requests_total" "fortress_smtp_connections_total")
    
    for metric in "${fortress_metrics[@]}"; do
        local query_result
        query_result=$(curl -sf "$PROMETHEUS_URL/api/v1/query?query=$metric" 2>/dev/null || echo "")
        
        if echo "$query_result" | jq -e '.data.result | length > 0' >/dev/null 2>&1; then
            log_success "Fortress metric '$metric' is available"
        else
            log_warning "Fortress metric '$metric' is not available yet"
        fi
    done
    
    log_success "Prometheus validation completed"
    return 0
}

validate_grafana() {
    log_info "Validating Grafana..."
    
    # Check if Grafana is accessible
    if ! check_url_accessible "$GRAFANA_URL/api/health" "Grafana"; then
        return 1
    fi
    
    # Check Grafana health
    local health_response
    health_response=$(curl -sf "$GRAFANA_URL/api/health" 2>/dev/null || echo "")
    
    if echo "$health_response" | jq -e '.database == "ok"' >/dev/null 2>&1; then
        log_success "Grafana database health check passed"
    else
        log_error "Grafana database health check failed"
        return 1
    fi
    
    # Check data sources (requires authentication - using default admin:admin)
    local datasources_response
    datasources_response=$(curl -sf -u admin:fortress123 "$GRAFANA_URL/api/datasources" 2>/dev/null || echo "")
    
    if [[ -n "$datasources_response" ]]; then
        local prometheus_ds
        prometheus_ds=$(echo "$datasources_response" | jq -r '.[] | select(.type == "prometheus") | .name' | head -1)
        local loki_ds
        loki_ds=$(echo "$datasources_response" | jq -r '.[] | select(.type == "loki") | .name' | head -1)
        local jaeger_ds
        jaeger_ds=$(echo "$datasources_response" | jq -r '.[] | select(.type == "jaeger") | .name' | head -1)
        
        [[ -n "$prometheus_ds" ]] && log_success "Prometheus data source configured: $prometheus_ds"
        [[ -n "$loki_ds" ]] && log_success "Loki data source configured: $loki_ds"
        [[ -n "$jaeger_ds" ]] && log_success "Jaeger data source configured: $jaeger_ds"
        
        if [[ -z "$prometheus_ds" && -z "$loki_ds" && -z "$jaeger_ds" ]]; then
            log_warning "No monitoring data sources found in Grafana"
        fi
    else
        log_warning "Could not retrieve Grafana data sources information"
    fi
    
    log_success "Grafana validation completed"
    return 0
}

validate_jaeger() {
    log_info "Validating Jaeger..."
    
    # Check if Jaeger Query UI is accessible
    if ! check_url_accessible "$JAEGER_URL" "Jaeger Query UI"; then
        return 1
    fi
    
    # Check Jaeger health
    if curl -sf "$JAEGER_URL/api/health" >/dev/null 2>&1; then
        log_success "Jaeger health check passed"
    else
        log_warning "Jaeger health endpoint not available (may be expected)"
    fi
    
    # Check if we can retrieve services
    local services_response
    services_response=$(curl -sf "$JAEGER_URL/api/services" 2>/dev/null || echo "")
    
    if [[ -n "$services_response" ]] && echo "$services_response" | jq -e '.data | length >= 0' >/dev/null 2>&1; then
        local service_count
        service_count=$(echo "$services_response" | jq -r '.data | length')
        log_success "Jaeger services endpoint accessible, found $service_count services"
    else
        log_warning "Could not retrieve services from Jaeger"
    fi
    
    log_success "Jaeger validation completed"
    return 0
}

validate_loki() {
    log_info "Validating Loki..."
    
    # Check if Loki is accessible
    if ! check_url_accessible "$LOKI_URL/ready" "Loki"; then
        return 1
    fi
    
    # Check Loki metrics endpoint
    if curl -sf "$LOKI_URL/metrics" >/dev/null 2>&1; then
        log_success "Loki metrics endpoint accessible"
    else
        log_error "Loki metrics endpoint not accessible"
        return 1
    fi
    
    # Try a simple label query
    local labels_response
    labels_response=$(curl -sf "$LOKI_URL/loki/api/v1/labels" 2>/dev/null || echo "")
    
    if [[ -n "$labels_response" ]] && echo "$labels_response" | jq -e '.status == "success"' >/dev/null 2>&1; then
        local label_count
        label_count=$(echo "$labels_response" | jq -r '.data | length')
        log_success "Loki labels endpoint accessible, found $label_count labels"
    else
        log_warning "Could not retrieve labels from Loki"
    fi
    
    log_success "Loki validation completed"
    return 0
}

validate_alertmanager() {
    log_info "Validating AlertManager..."
    
    # Check if AlertManager is accessible
    if ! check_url_accessible "$ALERTMANAGER_URL" "AlertManager"; then
        return 1
    fi
    
    # Check AlertManager health
    if curl -sf "$ALERTMANAGER_URL/-/healthy" >/dev/null 2>&1; then
        log_success "AlertManager health check passed"
    else
        log_error "AlertManager health check failed"
        return 1
    fi
    
    # Check if AlertManager is ready
    if curl -sf "$ALERTMANAGER_URL/-/ready" >/dev/null 2>&1; then
        log_success "AlertManager readiness check passed"
    else
        log_error "AlertManager readiness check failed"
        return 1
    fi
    
    # Check status
    local status_response
    status_response=$(curl -sf "$ALERTMANAGER_URL/api/v1/status" 2>/dev/null || echo "")
    
    if [[ -n "$status_response" ]] && echo "$status_response" | jq -e '.status == "success"' >/dev/null 2>&1; then
        local version
        version=$(echo "$status_response" | jq -r '.data.versionInfo.version')
        log_success "AlertManager status check passed (version: $version)"
    else
        log_warning "Could not retrieve AlertManager status"
    fi
    
    log_success "AlertManager validation completed"
    return 0
}

validate_exporters() {
    log_info "Validating Exporters..."
    
    # Node Exporter
    if curl -sf --max-time $TIMEOUT "http://localhost:9100/metrics" >/dev/null 2>&1; then
        log_success "Node Exporter is accessible"
    else
        log_error "Node Exporter is not accessible"
    fi
    
    # cAdvisor
    if curl -sf --max-time $TIMEOUT "http://localhost:8080/metrics" >/dev/null 2>&1; then
        log_success "cAdvisor is accessible"
    else
        log_error "cAdvisor is not accessible"
    fi
    
    # PostgreSQL Exporter
    if curl -sf --max-time $TIMEOUT "http://localhost:9187/metrics" >/dev/null 2>&1; then
        log_success "PostgreSQL Exporter is accessible"
    else
        log_error "PostgreSQL Exporter is not accessible"
    fi
    
    # Redis Exporter  
    if curl -sf --max-time $TIMEOUT "http://localhost:9121/metrics" >/dev/null 2>&1; then
        log_success "Redis Exporter is accessible"
    else
        log_error "Redis Exporter is not accessible"
    fi
    
    log_success "Exporters validation completed"
    return 0
}

validate_fortress_services() {
    log_info "Validating Fortress Service Metrics..."
    
    # Fortress Core
    if curl -sf --max-time $TIMEOUT "http://localhost:8025/metrics" >/dev/null 2>&1; then
        log_success "Fortress Core metrics endpoint is accessible"
    else
        log_warning "Fortress Core metrics endpoint is not accessible"
    fi
    
    # Check for fortress-specific metrics in Prometheus
    local fortress_services=("fortress-core" "fortress-smtp" "fortress-api" "fortress-plugins" "fortress-workflows")
    
    for service in "${fortress_services[@]}"; do
        local query_result
        query_result=$(curl -sf "$PROMETHEUS_URL/api/v1/query?query=up{job=\"$service\"}" 2>/dev/null || echo "")
        
        if echo "$query_result" | jq -e '.data.result[0].value[1] == "1"' >/dev/null 2>&1; then
            log_success "Service '$service' metrics are available in Prometheus"
        else
            log_warning "Service '$service' metrics are not available in Prometheus"
        fi
    done
    
    log_success "Fortress services validation completed"
    return 0
}

run_synthetic_tests() {
    log_info "Running synthetic monitoring tests..."
    
    # Test Prometheus query
    local test_query="up"
    local query_result
    query_result=$(curl -sf "$PROMETHEUS_URL/api/v1/query?query=$test_query" 2>/dev/null || echo "")
    
    if echo "$query_result" | jq -e '.status == "success"' >/dev/null 2>&1; then
        log_success "Prometheus query test passed"
    else
        log_error "Prometheus query test failed"
    fi
    
    # Test Grafana API
    if curl -sf -u admin:fortress123 "$GRAFANA_URL/api/org" >/dev/null 2>&1; then
        log_success "Grafana API test passed"
    else
        log_warning "Grafana API test failed (may require authentication setup)"
    fi
    
    # Test Loki query
    local loki_query='{job="prometheus"}'
    local loki_result
    loki_result=$(curl -sf "$LOKI_URL/loki/api/v1/query_range?query=$loki_query&start=$(date -d '1 hour ago' +%s)000000000&end=$(date +%s)000000000" 2>/dev/null || echo "")
    
    if echo "$loki_result" | jq -e '.status == "success"' >/dev/null 2>&1; then
        log_success "Loki query test passed"
    else
        log_warning "Loki query test failed (may not have data yet)"
    fi
    
    log_success "Synthetic tests completed"
    return 0
}

generate_validation_report() {
    log_info "Generating monitoring stack validation report..."
    
    local report_file="/tmp/fortress-monitoring-validation-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "validation_results": {
    "prometheus": {
      "accessible": $(curl -sf "$PROMETHEUS_URL" >/dev/null 2>&1 && echo "true" || echo "false"),
      "healthy": $(curl -sf "$PROMETHEUS_URL/-/healthy" >/dev/null 2>&1 && echo "true" || echo "false"),
      "ready": $(curl -sf "$PROMETHEUS_URL/-/ready" >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "grafana": {
      "accessible": $(curl -sf "$GRAFANA_URL/api/health" >/dev/null 2>&1 && echo "true" || echo "false"),
      "healthy": $(curl -sf "$GRAFANA_URL/api/health" 2>/dev/null | jq -e '.database == "ok"' >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "jaeger": {
      "accessible": $(curl -sf "$JAEGER_URL" >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "loki": {
      "accessible": $(curl -sf "$LOKI_URL/ready" >/dev/null 2>&1 && echo "true" || echo "false"),
      "metrics_endpoint": $(curl -sf "$LOKI_URL/metrics" >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "alertmanager": {
      "accessible": $(curl -sf "$ALERTMANAGER_URL" >/dev/null 2>&1 && echo "true" || echo "false"),
      "healthy": $(curl -sf "$ALERTMANAGER_URL/-/healthy" >/dev/null 2>&1 && echo "true" || echo "false"),
      "ready": $(curl -sf "$ALERTMANAGER_URL/-/ready" >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "exporters": {
      "node_exporter": $(curl -sf "http://localhost:9100/metrics" >/dev/null 2>&1 && echo "true" || echo "false"),
      "cadvisor": $(curl -sf "http://localhost:8080/metrics" >/dev/null 2>&1 && echo "true" || echo "false"),
      "postgres_exporter": $(curl -sf "http://localhost:9187/metrics" >/dev/null 2>&1 && echo "true" || echo "false"),
      "redis_exporter": $(curl -sf "http://localhost:9121/metrics" >/dev/null 2>&1 && echo "true" || echo "false")
    }
  }
}
EOF

    log_success "Validation report generated: $report_file"
    echo "$report_file"
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log_info "Starting Pat Fortress Monitoring Stack Validation"
    echo "======================================================="
    
    local validation_errors=0
    
    # Check prerequisites
    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl command not found. Please install curl."
        exit 1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq command not found. Please install jq."
        exit 1
    fi
    
    # Validate each component
    validate_prometheus || validation_errors=$((validation_errors + 1))
    echo
    
    validate_grafana || validation_errors=$((validation_errors + 1))
    echo
    
    validate_jaeger || validation_errors=$((validation_errors + 1))
    echo
    
    validate_loki || validation_errors=$((validation_errors + 1))
    echo
    
    validate_alertmanager || validation_errors=$((validation_errors + 1))
    echo
    
    validate_exporters || validation_errors=$((validation_errors + 1))
    echo
    
    validate_fortress_services || validation_errors=$((validation_errors + 1))
    echo
    
    run_synthetic_tests || validation_errors=$((validation_errors + 1))
    echo
    
    # Generate report
    local report_file
    report_file=$(generate_validation_report)
    
    # Summary
    echo "======================================================="
    if [ $validation_errors -eq 0 ]; then
        log_success "All monitoring stack components validated successfully!"
        log_info "Validation report: $report_file"
        echo
        log_info "Next steps:"
        echo "  1. Access Grafana: $GRAFANA_URL (admin/fortress123)"
        echo "  2. Access Prometheus: $PROMETHEUS_URL"
        echo "  3. Access Jaeger: $JAEGER_URL"
        echo "  4. Access AlertManager: $ALERTMANAGER_URL"
        echo
        exit 0
    else
        log_error "Validation completed with $validation_errors errors"
        log_info "Please check the logs above for details"
        log_info "Validation report: $report_file"
        exit 1
    fi
}

# Run main function
main "$@"