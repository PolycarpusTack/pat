#!/bin/bash
# =============================================================================
# Pat Fortress - Monitoring Stack Deployment Script
# Automated deployment of comprehensive monitoring infrastructure
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="/mnt/c/Projects/Pat"
COMPOSE_FILE="docker-compose.fortress.yml"
DATA_DIR="${DATA_DIR:-/var/lib/fortress}"
TIMEOUT=300

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

log_step() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

check_prerequisites() {
    log_step "Checking Prerequisites"
    
    local missing_tools=()
    
    # Check required tools
    for tool in docker docker-compose jq curl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        else
            log_success "$tool is available"
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log_success "All prerequisites met"
}

create_directories() {
    log_step "Creating Data Directories"
    
    local directories=(
        "$DATA_DIR/postgres/primary"
        "$DATA_DIR/postgres/replica"
        "$DATA_DIR/redis/master"
        "$DATA_DIR/kafka"
        "$DATA_DIR/app/storage"
        "$DATA_DIR/app/emails"
        "$DATA_DIR/app/plugins"
        "$DATA_DIR/app/workflows"
        "$DATA_DIR/app/workflow-state"
        "$DATA_DIR/monitoring/prometheus"
        "$DATA_DIR/monitoring/grafana"
        "$DATA_DIR/monitoring/loki"
        "$DATA_DIR/monitoring/alertmanager"
    )
    
    for dir in "${directories[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            log_success "Created directory: $dir"
        else
            log_warning "Could not create directory: $dir (may already exist)"
        fi
    done
    
    # Set proper permissions
    if command -v chown >/dev/null 2>&1; then
        log_info "Setting directory permissions..."
        sudo chown -R 1001:1001 "$DATA_DIR/monitoring" 2>/dev/null || log_warning "Could not set monitoring directory permissions"
    fi
}

generate_secrets() {
    log_step "Generating Secrets"
    
    # Generate random passwords
    local postgres_password
    postgres_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    local redis_password
    redis_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    local grafana_password
    grafana_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    # Create Docker secrets
    echo "$postgres_password" | docker secret create pat_postgres_password - 2>/dev/null || log_warning "Postgres password secret may already exist"
    echo "$redis_password" | docker secret create pat_redis_password - 2>/dev/null || log_warning "Redis password secret may already exist"
    
    # Generate JWT keys
    if ! docker secret ls | grep -q pat_jwt_private_key; then
        openssl genrsa -out /tmp/jwt_private.key 2048
        docker secret create pat_jwt_private_key /tmp/jwt_private.key
        rm /tmp/jwt_private.key
        log_success "JWT private key secret created"
    fi
    
    if ! docker secret ls | grep -q pat_jwt_public_key; then
        openssl genrsa -out /tmp/jwt_private_temp.key 2048
        openssl rsa -in /tmp/jwt_private_temp.key -pubout -out /tmp/jwt_public.key
        docker secret create pat_jwt_public_key /tmp/jwt_public.key
        rm /tmp/jwt_private_temp.key /tmp/jwt_public.key
        log_success "JWT public key secret created"
    fi
    
    # Generate self-signed SSL certificate
    if ! docker secret ls | grep -q pat_ssl_cert; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /tmp/fortress.key -out /tmp/fortress.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=fortress.pat.local" 2>/dev/null
        
        docker secret create pat_ssl_cert /tmp/fortress.crt
        docker secret create pat_ssl_key /tmp/fortress.key
        rm /tmp/fortress.crt /tmp/fortress.key
        log_success "SSL certificate secrets created"
    fi
    
    # Save credentials for reference
    cat > "$PROJECT_ROOT/monitoring-credentials.txt" << EOF
# Pat Fortress Monitoring Credentials
# Generated on: $(date)

# Database Credentials
POSTGRES_PASSWORD=$postgres_password
REDIS_PASSWORD=$redis_password

# Grafana Credentials  
GRAFANA_ADMIN_PASSWORD=$grafana_password

# URLs
GRAFANA_URL=https://fortress.pat.local/grafana/
PROMETHEUS_URL=https://fortress.pat.local/prometheus/
JAEGER_URL=https://fortress.pat.local/jaeger/
ALERTMANAGER_URL=https://fortress.pat.local/alertmanager/
EOF
    
    log_success "Secrets generated and saved to monitoring-credentials.txt"
}

update_prometheus_config() {
    log_step "Updating Prometheus Configuration"
    
    # Update prometheus.yml with AlertManager reference
    local prometheus_config="$PROJECT_ROOT/monitoring/prometheus/prometheus.yml"
    
    if grep -q "rule_files:" "$prometheus_config"; then
        log_info "Prometheus configuration includes alerting rules"
    else
        log_warning "Prometheus configuration may need manual update for alerting rules"
    fi
    
    # Validate Prometheus config
    if docker run --rm -v "$PROJECT_ROOT/monitoring/prometheus:/etc/prometheus" prom/prometheus:v2.47.0 \
        promtool check config /etc/prometheus/prometheus.yml >/dev/null 2>&1; then
        log_success "Prometheus configuration is valid"
    else
        log_error "Prometheus configuration validation failed"
        return 1
    fi
}

start_monitoring_stack() {
    log_step "Starting Monitoring Stack"
    
    cd "$PROJECT_ROOT"
    
    # Set environment variables
    export DATA_DIR="$DATA_DIR"
    export GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-fortress123}"
    
    # Start only monitoring services first
    log_info "Starting core infrastructure services..."
    docker-compose -f "$COMPOSE_FILE" up -d postgres-primary redis-master kafka
    
    # Wait for infrastructure to be ready
    log_info "Waiting for infrastructure services to be ready..."
    sleep 30
    
    # Start monitoring services
    log_info "Starting monitoring services..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        prometheus grafana jaeger loki promtail alertmanager \
        node-exporter cadvisor \
        postgres-exporter-primary redis-exporter kafka-exporter nginx-prometheus-exporter
    
    # Start Fortress application services
    log_info "Starting Fortress application services..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        fortress-core fortress-smtp fortress-api fortress-plugins fortress-workflows fortress-frontend
    
    # Start reverse proxy
    log_info "Starting reverse proxy..."
    docker-compose -f "$COMPOSE_FILE" up -d nginx
    
    log_success "Monitoring stack deployment initiated"
}

wait_for_services() {
    log_step "Waiting for Services to be Ready"
    
    local services=(
        "http://localhost:9090/-/ready:Prometheus"
        "http://localhost:3000/api/health:Grafana"
        "http://localhost:16686:Jaeger"
        "http://localhost:3100/ready:Loki"
        "http://localhost:9093/-/ready:AlertManager"
    )
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r url name <<< "$service_info"
        log_info "Waiting for $name to be ready..."
        
        local count=0
        local max_attempts=30
        
        while [ $count -lt $max_attempts ]; do
            if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
                log_success "$name is ready"
                break
            fi
            
            count=$((count + 1))
            if [ $count -eq $max_attempts ]; then
                log_error "$name failed to become ready after $max_attempts attempts"
                return 1
            fi
            
            sleep 10
        done
    done
    
    log_success "All services are ready"
}

configure_grafana_datasources() {
    log_step "Configuring Grafana Data Sources"
    
    # Wait for Grafana to be fully ready
    sleep 30
    
    local grafana_url="http://localhost:3000"
    local auth="admin:${GRAFANA_ADMIN_PASSWORD:-fortress123}"
    
    # Check if data sources are already configured
    local datasources_response
    datasources_response=$(curl -sf -u "$auth" "$grafana_url/api/datasources" 2>/dev/null || echo "[]")
    
    local prometheus_exists
    prometheus_exists=$(echo "$datasources_response" | jq -r '.[] | select(.type == "prometheus") | .name' | head -1)
    
    if [[ -n "$prometheus_exists" ]]; then
        log_success "Grafana data sources are already configured"
    else
        log_info "Data sources will be provisioned automatically via configuration files"
    fi
    
    # Import dashboards
    log_info "Grafana dashboards will be provisioned automatically"
}

run_validation() {
    log_step "Running Monitoring Stack Validation"
    
    local validation_script="$PROJECT_ROOT/scripts/monitoring/validate-monitoring-stack.sh"
    
    if [[ -f "$validation_script" ]]; then
        chmod +x "$validation_script"
        if "$validation_script"; then
            log_success "Monitoring stack validation passed"
        else
            log_warning "Monitoring stack validation had some issues (check logs above)"
        fi
    else
        log_warning "Validation script not found: $validation_script"
    fi
}

show_access_info() {
    log_step "Access Information"
    
    cat << EOF

${GREEN}Pat Fortress Monitoring Stack Deployed Successfully!${NC}

${BLUE}Access URLs:${NC}
  • Grafana Dashboard:    http://localhost:3000 (admin / fortress123)
  • Prometheus:           http://localhost:9090  
  • Jaeger Tracing:       http://localhost:16686
  • AlertManager:         http://localhost:9093

${BLUE}Monitoring Endpoints:${NC}
  • Node Exporter:        http://localhost:9100/metrics
  • cAdvisor:            http://localhost:8080/metrics  
  • PostgreSQL Exporter: http://localhost:9187/metrics
  • Redis Exporter:      http://localhost:9121/metrics

${BLUE}Fortress Services:${NC}
  • Core Application:    http://localhost:8025
  • SMTP Server:         localhost:1025
  • Frontend:            http://localhost:3000

${BLUE}Next Steps:${NC}
  1. Import custom dashboards in Grafana
  2. Configure AlertManager notification channels
  3. Review and adjust alerting rules
  4. Set up log retention policies
  5. Configure backup and disaster recovery

${BLUE}Credentials:${NC}
  See monitoring-credentials.txt for generated passwords

${YELLOW}Note:${NC} It may take a few minutes for all metrics to appear in dashboards.

EOF
}

cleanup_on_error() {
    log_error "Deployment failed. Cleaning up..."
    
    cd "$PROJECT_ROOT"
    docker-compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    
    # Remove created secrets (optional)
    # docker secret rm pat_postgres_password pat_redis_password pat_jwt_private_key pat_jwt_public_key pat_ssl_cert pat_ssl_key 2>/dev/null || true
    
    exit 1
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log_info "Starting Pat Fortress Monitoring Stack Deployment"
    echo "====================================================="
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Run deployment steps
    check_prerequisites
    create_directories
    generate_secrets
    update_prometheus_config
    start_monitoring_stack
    wait_for_services
    configure_grafana_datasources
    run_validation
    show_access_info
    
    log_success "Pat Fortress Monitoring Stack deployment completed successfully!"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Pat Fortress Monitoring Stack Deployment"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --data-dir     Specify data directory (default: /var/lib/fortress)"
        echo
        echo "Environment Variables:"
        echo "  DATA_DIR              Data directory path"
        echo "  GRAFANA_ADMIN_PASSWORD Grafana admin password"
        echo
        exit 0
        ;;
    --data-dir)
        if [[ -n "${2:-}" ]]; then
            DATA_DIR="$2"
            shift 2
        else
            log_error "--data-dir requires a directory path"
            exit 1
        fi
        ;;
esac

# Run main function
main "$@"