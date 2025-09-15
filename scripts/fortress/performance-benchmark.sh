#!/bin/bash

# Pat Fortress Performance Benchmark Validation Script
# Validates claimed performance metrics: 10,500 req/s and 99.97% uptime

set -euo pipefail

# Configuration
FORTRESS_HTTP_ENDPOINT="http://localhost:8025"
FORTRESS_SMTP_ENDPOINT="localhost:1025"
BENCHMARK_DURATION="60s"
CONCURRENT_CONNECTIONS="100"
TARGET_RPS="10500"
TARGET_UPTIME="99.97"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create benchmark results directory
BENCHMARK_RESULTS_DIR="/mnt/c/Projects/Pat/benchmark-results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BENCHMARK_RESULTS_DIR"

log_info "Starting Pat Fortress Performance Benchmark Validation"
log_info "Results will be saved to: $BENCHMARK_RESULTS_DIR"

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if wrk is installed
    if ! command -v wrk &> /dev/null; then
        log_error "wrk (load testing tool) is not installed. Please install it first."
        log_info "Install wrk: sudo apt-get install wrk (Ubuntu/Debian)"
        exit 1
    fi
    
    # Check if fortress is running
    if ! curl -s "$FORTRESS_HTTP_ENDPOINT/api/v3/health" &> /dev/null; then
        log_error "Pat Fortress is not running at $FORTRESS_HTTP_ENDPOINT"
        log_info "Please start Pat Fortress first: go run main.go"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# HTTP API Performance Benchmark
benchmark_http_api() {
    log_info "Running HTTP API performance benchmark..."
    
    # Test different endpoints
    local endpoints=(
        "/api/v1/messages"
        "/api/v2/messages"
        "/api/v3/health"
        "/api/v3/metrics"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log_info "Benchmarking endpoint: $endpoint"
        
        local output_file="$BENCHMARK_RESULTS_DIR/http_${endpoint##*/}_benchmark.txt"
        
        wrk -t12 -c"$CONCURRENT_CONNECTIONS" -d"$BENCHMARK_DURATION" \
            --latency "$FORTRESS_HTTP_ENDPOINT$endpoint" \
            > "$output_file" 2>&1
        
        # Extract key metrics
        local rps=$(grep "Requests/sec:" "$output_file" | awk '{print $2}')
        local avg_latency=$(grep "Latency" "$output_file" | awk '{print $2}')
        
        log_info "Endpoint $endpoint - RPS: $rps, Avg Latency: $avg_latency"
        
        # Store results in JSON format
        cat > "$BENCHMARK_RESULTS_DIR/http_${endpoint##*/}_results.json" << EOF
{
  "endpoint": "$endpoint",
  "requests_per_second": "$rps",
  "average_latency": "$avg_latency",
  "concurrent_connections": $CONCURRENT_CONNECTIONS,
  "duration": "$BENCHMARK_DURATION",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    done
    
    log_success "HTTP API benchmark completed"
}

# SMTP Performance Benchmark
benchmark_smtp() {
    log_info "Running SMTP performance benchmark..."
    
    # Create test email content
    local test_email_file="$BENCHMARK_RESULTS_DIR/test_email.eml"
    cat > "$test_email_file" << 'EOF'
From: test@fortress.local
To: benchmark@fortress.local
Subject: Performance Benchmark Test Email
Date: $(date -R)

This is a performance benchmark test email for Pat Fortress.
Content length: 256 bytes for consistent testing.
EOF

    # SMTP benchmark using swaks (if available) or custom script
    if command -v swaks &> /dev/null; then
        log_info "Using swaks for SMTP benchmarking..."
        
        local smtp_start_time=$(date +%s)
        local smtp_success_count=0
        local smtp_total_attempts=1000
        
        for ((i=1; i<=smtp_total_attempts; i++)); do
            if swaks --to "benchmark-$i@fortress.local" \
                     --from "test@fortress.local" \
                     --server "$FORTRESS_SMTP_ENDPOINT" \
                     --body "Benchmark email $i" \
                     --suppress-data &> /dev/null; then
                ((smtp_success_count++))
            fi
            
            if ((i % 100 == 0)); then
                log_info "SMTP benchmark progress: $i/$smtp_total_attempts"
            fi
        done
        
        local smtp_end_time=$(date +%s)
        local smtp_duration=$((smtp_end_time - smtp_start_time))
        local smtp_rps=$((smtp_success_count / smtp_duration))
        local smtp_success_rate=$(echo "scale=2; $smtp_success_count * 100 / $smtp_total_attempts" | bc)
        
        # Store SMTP results
        cat > "$BENCHMARK_RESULTS_DIR/smtp_results.json" << EOF
{
  "protocol": "SMTP",
  "total_attempts": $smtp_total_attempts,
  "successful_deliveries": $smtp_success_count,
  "success_rate": "$smtp_success_rate%",
  "requests_per_second": $smtp_rps,
  "duration_seconds": $smtp_duration,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
        
        log_success "SMTP benchmark completed: $smtp_rps RPS, $smtp_success_rate% success rate"
    else
        log_warn "swaks not available, skipping SMTP benchmark"
    fi
}

# Uptime and Reliability Test
test_uptime_reliability() {
    log_info "Running uptime and reliability test..."
    
    local uptime_test_duration=300  # 5 minutes for demonstration
    local check_interval=1
    local total_checks=$((uptime_test_duration / check_interval))
    local successful_checks=0
    
    log_info "Testing reliability for $uptime_test_duration seconds..."
    
    for ((i=1; i<=total_checks; i++)); do
        if curl -s -f "$FORTRESS_HTTP_ENDPOINT/api/v3/health" &> /dev/null; then
            ((successful_checks++))
        fi
        
        sleep $check_interval
        
        if ((i % 60 == 0)); then
            local current_uptime=$(echo "scale=2; $successful_checks * 100 / $i" | bc)
            log_info "Current uptime: $current_uptime% ($successful_checks/$i checks)"
        fi
    done
    
    local final_uptime=$(echo "scale=2; $successful_checks * 100 / $total_checks" | bc)
    
    # Store uptime results
    cat > "$BENCHMARK_RESULTS_DIR/uptime_results.json" << EOF
{
  "test_duration_seconds": $uptime_test_duration,
  "total_health_checks": $total_checks,
  "successful_checks": $successful_checks,
  "uptime_percentage": "$final_uptime%",
  "target_uptime": "$TARGET_UPTIME%",
  "meets_target": $(if (( $(echo "$final_uptime >= $TARGET_UPTIME" | bc -l) )); then echo "true"; else echo "false"; fi),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    
    log_success "Uptime test completed: $final_uptime% uptime"
}

# Analyze results and generate report
analyze_results() {
    log_info "Analyzing benchmark results..."
    
    local summary_file="$BENCHMARK_RESULTS_DIR/benchmark_summary.json"
    local report_file="$BENCHMARK_RESULTS_DIR/fortress_performance_report.md"
    
    # Calculate overall RPS from HTTP benchmarks
    local max_rps=0
    local avg_rps=0
    local endpoint_count=0
    
    for json_file in "$BENCHMARK_RESULTS_DIR"/http_*_results.json; do
        if [[ -f "$json_file" ]]; then
            local rps=$(jq -r '.requests_per_second' "$json_file" | sed 's/[^0-9.]//g')
            if [[ -n "$rps" && "$rps" != "null" ]]; then
                max_rps=$(echo "$max_rps $rps" | awk '{print ($1>$2)?$1:$2}')
                avg_rps=$(echo "$avg_rps + $rps" | bc)
                ((endpoint_count++))
            fi
        fi
    done
    
    if [[ $endpoint_count -gt 0 ]]; then
        avg_rps=$(echo "scale=2; $avg_rps / $endpoint_count" | bc)
    fi
    
    # Check if performance targets are met
    local rps_target_met=$(if (( $(echo "$max_rps >= $TARGET_RPS" | bc -l) )); then echo "true"; else echo "false"; fi)
    
    # Get uptime result
    local uptime_result="99.00"  # Default if uptime test wasn't run
    local uptime_target_met="false"
    
    if [[ -f "$BENCHMARK_RESULTS_DIR/uptime_results.json" ]]; then
        uptime_result=$(jq -r '.uptime_percentage' "$BENCHMARK_RESULTS_DIR/uptime_results.json" | sed 's/%//')
        uptime_target_met=$(jq -r '.meets_target' "$BENCHMARK_RESULTS_DIR/uptime_results.json")
    fi
    
    # Generate summary JSON
    cat > "$summary_file" << EOF
{
  "fortress_version": "2.0.0",
  "benchmark_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "performance_targets": {
    "target_rps": $TARGET_RPS,
    "target_uptime": "$TARGET_UPTIME%"
  },
  "measured_performance": {
    "max_rps": $max_rps,
    "average_rps": $avg_rps,
    "uptime_percentage": "$uptime_result%"
  },
  "target_compliance": {
    "rps_target_met": $rps_target_met,
    "uptime_target_met": $uptime_target_met,
    "overall_certification": $(if [[ "$rps_target_met" == "true" && "$uptime_target_met" == "true" ]]; then echo "\"CERTIFIED\""; else echo "\"NEEDS_IMPROVEMENT\""; fi)
  }
}
EOF

    # Generate detailed report
    cat > "$report_file" << EOF
# Pat Fortress Performance Benchmark Report

**Generated:** $(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)  
**Fortress Version:** 2.0.0  
**Benchmark Duration:** $BENCHMARK_DURATION  

## Performance Targets

- **Target RPS:** $TARGET_RPS requests/second
- **Target Uptime:** $TARGET_UPTIME%

## Measured Performance

- **Maximum RPS:** $max_rps requests/second
- **Average RPS:** $avg_rps requests/second  
- **Measured Uptime:** $uptime_result%

## Target Compliance

- **RPS Target Met:** $rps_target_met
- **Uptime Target Met:** $uptime_target_met
- **Overall Certification:** $(if [[ "$rps_target_met" == "true" && "$uptime_target_met" == "true" ]]; then echo "✅ CERTIFIED"; else echo "❌ NEEDS IMPROVEMENT"; fi)

## Detailed Results

Performance benchmark results are available in the following files:
- HTTP API benchmarks: \`http_*_benchmark.txt\`
- SMTP benchmarks: \`smtp_results.json\`
- Uptime test: \`uptime_results.json\`
- Summary: \`benchmark_summary.json\`

## Recommendations

$(if [[ "$rps_target_met" != "true" ]]; then echo "- **RPS Improvement Needed:** Current maximum RPS ($max_rps) is below target ($TARGET_RPS). Consider optimizing HTTP handlers, database queries, and caching strategies."; fi)
$(if [[ "$uptime_target_met" != "true" ]]; then echo "- **Uptime Improvement Needed:** Current uptime ($uptime_result%) is below target ($TARGET_UPTIME%). Investigate reliability issues and implement better error handling."; fi)
$(if [[ "$rps_target_met" == "true" && "$uptime_target_met" == "true" ]]; then echo "- **Excellent Performance:** All targets met. Pat Fortress is certified for production deployment."; fi)
EOF

    log_success "Benchmark analysis completed"
    log_info "Summary: $summary_file"
    log_info "Report: $report_file"
}

# Main execution
main() {
    check_prerequisites
    benchmark_http_api
    benchmark_smtp
    test_uptime_reliability
    analyze_results
    
    local overall_status
    if [[ -f "$BENCHMARK_RESULTS_DIR/benchmark_summary.json" ]]; then
        overall_status=$(jq -r '.target_compliance.overall_certification' "$BENCHMARK_RESULTS_DIR/benchmark_summary.json")
        
        if [[ "$overall_status" == "CERTIFIED" ]]; then
            log_success "🏆 Pat Fortress Performance Certification: PASSED"
            log_success "All performance targets have been met!"
        else
            log_warn "⚠️  Pat Fortress Performance Certification: NEEDS IMPROVEMENT"
            log_warn "Some performance targets were not met. See detailed report for recommendations."
        fi
    fi
    
    log_info "Benchmark complete. Results saved to: $BENCHMARK_RESULTS_DIR"
}

# Execute if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi