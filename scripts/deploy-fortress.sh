#!/bin/bash
# =============================================================================
# Pat Fortress - Complete Infrastructure Deployment Script
# Production-Ready Deployment Automation with Multi-Cloud Support
# =============================================================================

set -euo pipefail

# =============================================================================
# Global Variables and Configuration
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_DIR="${PROJECT_ROOT}/logs/deployment"
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly TERRAFORM_DIR="${PROJECT_ROOT}/terraform"
readonly K8S_DIR="${PROJECT_ROOT}/k8s"
readonly DOCKER_COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.fortress.yml"

# Create log directory
mkdir -p "$LOG_DIR"

# Logging setup
readonly LOG_FILE="${LOG_DIR}/fortress-deployment-$(date +%Y%m%d-%H%M%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Default configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
AWS_REGION="${AWS_REGION:-us-east-1}"
DEPLOYMENT_MODE="${DEPLOYMENT_MODE:-kubernetes}" # docker-compose, kubernetes, or both
SKIP_TERRAFORM="${SKIP_TERRAFORM:-false}"
SKIP_DOCKER_BUILD="${SKIP_DOCKER_BUILD:-false}"
SKIP_MONITORING="${SKIP_MONITORING:-false}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_RECREATE="${FORCE_RECREATE:-false}"
VERSION="${VERSION:-latest}"

# =============================================================================
# Helper Functions
# =============================================================================

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $*${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $*${NC}" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*${NC}" >&2
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $*${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $*${NC}"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] DEBUG: $*${NC}"
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    local tools=("docker" "docker-compose" "terraform" "kubectl" "helm" "aws")
    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        error "Please install them before continuing."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        error "AWS credentials not configured"
        exit 1
    fi
    
    # Check Terraform version
    local tf_version
    tf_version=$(terraform version -json | jq -r '.terraform_version' 2>/dev/null || echo "unknown")
    if [[ "$tf_version" == "unknown" ]]; then
        error "Could not determine Terraform version"
        exit 1
    fi
    
    success "Prerequisites check passed"
    info "Terraform version: $tf_version"
    info "Docker version: $(docker --version)"
    info "kubectl version: $(kubectl version --client --output=yaml | grep gitVersion | cut -d'"' -f4)"
    info "Helm version: $(helm version --short)"
    info "AWS CLI version: $(aws --version)"
}

# Load environment configuration
load_environment() {
    info "Loading environment configuration for: $ENVIRONMENT"
    
    local env_file="${CONFIG_DIR}/environments/${ENVIRONMENT}.env"
    if [[ -f "$env_file" ]]; then
        # shellcheck source=/dev/null
        source "$env_file"
        success "Environment configuration loaded from $env_file"
    else
        warn "Environment file not found: $env_file"
        warn "Using default configuration"
    fi
    
    # Validate required environment variables
    local required_vars=("AWS_REGION" "DOMAIN_NAME")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        error "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi
    
    export ENVIRONMENT AWS_REGION VERSION
}

# Build Docker images
build_docker_images() {
    if [[ "$SKIP_DOCKER_BUILD" == "true" ]]; then
        info "Skipping Docker build (SKIP_DOCKER_BUILD=true)"
        return 0
    fi
    
    info "Building Fortress Docker images..."
    
    local images=(
        "fortress-core:Dockerfile.fortress-core"
        "fortress-smtp:Dockerfile.smtp"
        "fortress-api:Dockerfile.api"
        "fortress-plugins:Dockerfile.plugins"
        "fortress-workflows:Dockerfile.workflows"
        "fortress-frontend:frontend/Dockerfile"
    )
    
    for image_info in "${images[@]}"; do
        local image_name="${image_info%%:*}"
        local dockerfile="${image_info##*:}"
        
        info "Building $image_name..."
        
        if [[ "$DRY_RUN" == "true" ]]; then
            info "[DRY RUN] Would build: docker build -f $dockerfile -t fortress/$image_name:$VERSION ."
        else
            docker build \
                -f "$dockerfile" \
                -t "fortress/$image_name:$VERSION" \
                -t "fortress/$image_name:latest" \
                --target production \
                --build-arg VERSION="$VERSION" \
                --build-arg ENVIRONMENT="$ENVIRONMENT" \
                .
        fi
        
        success "Built fortress/$image_name:$VERSION"
    done
    
    success "All Docker images built successfully"
}

# Deploy Terraform infrastructure
deploy_terraform() {
    if [[ "$SKIP_TERRAFORM" == "true" ]]; then
        info "Skipping Terraform deployment (SKIP_TERRAFORM=true)"
        return 0
    fi
    
    info "Deploying Terraform infrastructure..."
    
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform
    info "Initializing Terraform..."
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would run: terraform init"
    else
        terraform init -upgrade
    fi
    
    # Validate Terraform configuration
    info "Validating Terraform configuration..."
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would run: terraform validate"
    else
        terraform validate
    fi
    
    # Plan Terraform changes
    info "Planning Terraform changes..."
    local plan_file="${LOG_DIR}/terraform-plan-$(date +%Y%m%d-%H%M%S).tfplan"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would run: terraform plan -out=$plan_file"
    else
        terraform plan \
            -var="environment=$ENVIRONMENT" \
            -var="aws_region=$AWS_REGION" \
            -var="version=$VERSION" \
            -out="$plan_file"
    fi
    
    # Apply Terraform changes
    if [[ "$DRY_RUN" != "true" ]]; then
        info "Applying Terraform changes..."
        terraform apply "$plan_file"
        success "Terraform infrastructure deployed successfully"
        
        # Save outputs
        terraform output -json > "${LOG_DIR}/terraform-outputs.json"
        info "Terraform outputs saved to ${LOG_DIR}/terraform-outputs.json"
    else
        info "[DRY RUN] Would apply Terraform plan"
    fi
    
    cd "$PROJECT_ROOT"
}

# Deploy to Kubernetes
deploy_kubernetes() {
    if [[ "$DEPLOYMENT_MODE" != "kubernetes" && "$DEPLOYMENT_MODE" != "both" ]]; then
        info "Skipping Kubernetes deployment (mode: $DEPLOYMENT_MODE)"
        return 0
    fi
    
    info "Deploying to Kubernetes..."
    
    # Get cluster credentials
    local cluster_name
    cluster_name=$(terraform -chdir="$TERRAFORM_DIR" output -raw cluster_name 2>/dev/null || echo "pat-fortress-${ENVIRONMENT}")
    
    info "Configuring kubectl for cluster: $cluster_name"
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would run: aws eks update-kubeconfig --region $AWS_REGION --name $cluster_name"
    else
        aws eks update-kubeconfig --region "$AWS_REGION" --name "$cluster_name"
    fi
    
    # Apply Kubernetes manifests
    info "Applying Kubernetes manifests..."
    
    local manifests=(
        "namespace.yaml"
        "secrets.yaml"
        "configmaps.yaml"
        "persistent-volumes.yaml"
        "deployments.yaml"
        "services.yaml"
        "hpa.yaml"
    )
    
    for manifest in "${manifests[@]}"; do
        local manifest_path="$K8S_DIR/$manifest"
        if [[ -f "$manifest_path" ]]; then
            info "Applying $manifest..."
            if [[ "$DRY_RUN" == "true" ]]; then
                info "[DRY RUN] Would run: kubectl apply -f $manifest_path"
            else
                kubectl apply -f "$manifest_path"
            fi
        else
            warn "Manifest not found: $manifest_path"
        fi
    done
    
    # Wait for deployments to be ready
    if [[ "$DRY_RUN" != "true" ]]; then
        info "Waiting for deployments to be ready..."
        kubectl wait --for=condition=available --timeout=600s deployment --all -n fortress
        success "All deployments are ready"
    fi
    
    success "Kubernetes deployment completed"
}

# Deploy with Docker Compose
deploy_docker_compose() {
    if [[ "$DEPLOYMENT_MODE" != "docker-compose" && "$DEPLOYMENT_MODE" != "both" ]]; then
        info "Skipping Docker Compose deployment (mode: $DEPLOYMENT_MODE)"
        return 0
    fi
    
    info "Deploying with Docker Compose..."
    
    # Create necessary directories
    local data_dirs=(
        "/var/lib/fortress/postgres/primary"
        "/var/lib/fortress/postgres/replica" 
        "/var/lib/fortress/redis/master"
        "/var/lib/fortress/kafka"
        "/var/lib/fortress/app/storage"
        "/var/lib/fortress/app/emails"
        "/var/lib/fortress/app/plugins"
        "/var/lib/fortress/app/workflows"
        "/var/lib/fortress/app/workflow-state"
        "/var/lib/fortress/monitoring/prometheus"
        "/var/lib/fortress/monitoring/grafana"
        "/var/lib/fortress/monitoring/loki"
    )
    
    for dir in "${data_dirs[@]}"; do
        if [[ "$DRY_RUN" == "true" ]]; then
            info "[DRY RUN] Would create directory: $dir"
        else
            sudo mkdir -p "$dir"
            sudo chown -R 1001:1001 "$dir"
        fi
    done
    
    # Deploy services
    local compose_args=(
        "-f" "$DOCKER_COMPOSE_FILE"
        "--project-name" "fortress-${ENVIRONMENT}"
    )
    
    if [[ "$FORCE_RECREATE" == "true" ]]; then
        compose_args+=("--force-recreate")
    fi
    
    info "Starting Fortress services..."
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would run: docker-compose ${compose_args[*]} up -d"
    else
        docker-compose "${compose_args[@]}" up -d
        
        # Wait for services to be healthy
        info "Waiting for services to be healthy..."
        sleep 30
        
        # Check service health
        check_service_health_docker_compose
    fi
    
    success "Docker Compose deployment completed"
}

# Check service health for Docker Compose
check_service_health_docker_compose() {
    info "Checking service health..."
    
    local services=(
        "fortress-postgres-primary:5432"
        "fortress-redis-master:6379"
        "fortress-kafka:9092"
        "fortress-core:8025"
        "fortress-smtp:1025"
        "fortress-api:8025"
        "fortress-frontend:3000"
        "fortress-nginx:80"
    )
    
    local unhealthy_services=()
    
    for service_info in "${services[@]}"; do
        local service_name="${service_info%%:*}"
        local port="${service_info##*:}"
        
        info "Checking $service_name..."
        
        if docker-compose -f "$DOCKER_COMPOSE_FILE" ps "$service_name" | grep -q "healthy\|Up"; then
            success "$service_name is healthy"
        else
            error "$service_name is not healthy"
            unhealthy_services+=("$service_name")
        fi
    done
    
    if [[ ${#unhealthy_services[@]} -gt 0 ]]; then
        error "Unhealthy services detected: ${unhealthy_services[*]}"
        return 1
    fi
    
    success "All services are healthy"
}

# Deploy monitoring stack
deploy_monitoring() {
    if [[ "$SKIP_MONITORING" == "true" ]]; then
        info "Skipping monitoring deployment (SKIP_MONITORING=true)"
        return 0
    fi
    
    info "Deploying monitoring stack..."
    
    if [[ "$DEPLOYMENT_MODE" == "kubernetes" || "$DEPLOYMENT_MODE" == "both" ]]; then
        deploy_monitoring_kubernetes
    fi
    
    # Monitoring is included in Docker Compose deployment
    if [[ "$DEPLOYMENT_MODE" == "docker-compose" ]]; then
        info "Monitoring stack deployed with Docker Compose"
    fi
    
    success "Monitoring deployment completed"
}

# Deploy monitoring to Kubernetes
deploy_monitoring_kubernetes() {
    info "Deploying monitoring to Kubernetes..."
    
    # Add Prometheus Helm repository
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would add Helm repositories"
    else
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
        helm repo add grafana https://grafana.github.io/helm-charts
        helm repo update
    fi
    
    # Deploy Prometheus
    info "Deploying Prometheus..."
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would deploy Prometheus with Helm"
    else
        helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
            --namespace fortress \
            --create-namespace \
            --values "${CONFIG_DIR}/monitoring/prometheus-values.yaml" \
            --wait
    fi
    
    # Deploy Grafana dashboards
    info "Deploying custom Grafana dashboards..."
    if [[ "$DRY_RUN" == "true" ]]; then
        info "[DRY RUN] Would deploy Grafana dashboards"
    else
        kubectl apply -f "${CONFIG_DIR}/monitoring/grafana-dashboards.yaml" -n fortress
    fi
    
    success "Monitoring deployed to Kubernetes"
}

# Run post-deployment tests
run_post_deployment_tests() {
    info "Running post-deployment tests..."
    
    local test_script="${SCRIPT_DIR}/test-fortress-deployment.sh"
    if [[ -f "$test_script" && "$DRY_RUN" != "true" ]]; then
        info "Running deployment tests..."
        bash "$test_script" --environment "$ENVIRONMENT" --mode "$DEPLOYMENT_MODE"
    else
        warn "Test script not found or dry run mode: $test_script"
    fi
    
    success "Post-deployment tests completed"
}

# Cleanup on failure
cleanup_on_failure() {
    error "Deployment failed. Performing cleanup..."
    
    # Add cleanup logic here
    if [[ "$DEPLOYMENT_MODE" == "docker-compose" || "$DEPLOYMENT_MODE" == "both" ]]; then
        warn "Stopping Docker Compose services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" --project-name "fortress-${ENVIRONMENT}" down || true
    fi
    
    error "Deployment failed. Check logs at: $LOG_FILE"
    exit 1
}

# Generate deployment summary
generate_deployment_summary() {
    info "Generating deployment summary..."
    
    local summary_file="${LOG_DIR}/deployment-summary-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$summary_file" << EOF
# Pat Fortress Deployment Summary
Generated: $(date)
Environment: $ENVIRONMENT
Version: $VERSION
Deployment Mode: $DEPLOYMENT_MODE
AWS Region: $AWS_REGION

## Infrastructure Components
- Terraform: $(if [[ "$SKIP_TERRAFORM" == "true" ]]; then echo "Skipped"; else echo "Deployed"; fi)
- Kubernetes: $(if [[ "$DEPLOYMENT_MODE" == "kubernetes" || "$DEPLOYMENT_MODE" == "both" ]]; then echo "Deployed"; else echo "Skipped"; fi)
- Docker Compose: $(if [[ "$DEPLOYMENT_MODE" == "docker-compose" || "$DEPLOYMENT_MODE" == "both" ]]; then echo "Deployed"; else echo "Skipped"; fi)
- Monitoring: $(if [[ "$SKIP_MONITORING" == "true" ]]; then echo "Skipped"; else echo "Deployed"; fi)

## Access Information
EOF

    if [[ "$DEPLOYMENT_MODE" == "kubernetes" || "$DEPLOYMENT_MODE" == "both" ]]; then
        if [[ -f "${LOG_DIR}/terraform-outputs.json" && "$DRY_RUN" != "true" ]]; then
            local domain_name
            domain_name=$(jq -r '.domain_name.value' "${LOG_DIR}/terraform-outputs.json" 2>/dev/null || echo "N/A")
            echo "- Web Interface: https://$domain_name" >> "$summary_file"
            echo "- SMTP Server: $domain_name:1025" >> "$summary_file"
        fi
    fi
    
    if [[ "$DEPLOYMENT_MODE" == "docker-compose" || "$DEPLOYMENT_MODE" == "both" ]]; then
        echo "- Web Interface: https://localhost" >> "$summary_file"
        echo "- SMTP Server: localhost:1025" >> "$summary_file"
        echo "- Grafana: http://localhost:3001" >> "$summary_file"
        echo "- Prometheus: http://localhost:9090" >> "$summary_file"
    fi
    
    cat >> "$summary_file" << EOF

## Log Files
- Deployment Log: $LOG_FILE
- Summary: $summary_file

## Next Steps
1. Verify service health
2. Run integration tests
3. Configure monitoring alerts
4. Set up backup procedures

Deployment completed successfully!
EOF
    
    success "Deployment summary generated: $summary_file"
    
    # Display summary
    info "=== DEPLOYMENT SUMMARY ==="
    cat "$summary_file"
}

# Print usage information
print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Pat Fortress infrastructure and applications.

OPTIONS:
    -e, --environment ENV       Deployment environment (default: production)
    -r, --region REGION         AWS region (default: us-east-1)
    -m, --mode MODE            Deployment mode: docker-compose, kubernetes, or both (default: kubernetes)
    -v, --version VERSION      Application version (default: latest)
    --skip-terraform           Skip Terraform infrastructure deployment
    --skip-docker-build        Skip Docker image builds
    --skip-monitoring          Skip monitoring stack deployment
    --force-recreate           Force recreate all containers/resources
    --dry-run                  Show what would be done without executing
    --debug                    Enable debug output
    -h, --help                 Show this help message

ENVIRONMENT VARIABLES:
    ENVIRONMENT                Deployment environment
    AWS_REGION                 AWS region
    DEPLOYMENT_MODE            Deployment mode
    VERSION                    Application version
    SKIP_TERRAFORM             Skip Terraform (true/false)
    SKIP_DOCKER_BUILD          Skip Docker builds (true/false)
    SKIP_MONITORING            Skip monitoring (true/false)
    DRY_RUN                    Dry run mode (true/false)
    FORCE_RECREATE             Force recreate (true/false)
    DEBUG                      Debug mode (true/false)

EXAMPLES:
    # Deploy to production with Kubernetes
    $0 --environment production --mode kubernetes

    # Deploy locally with Docker Compose
    $0 --environment local --mode docker-compose

    # Dry run deployment
    $0 --dry-run --environment staging

    # Deploy with custom version
    $0 --version v2.1.0 --environment production

    # Skip infrastructure and deploy application only
    $0 --skip-terraform --environment production

EOF
}

# =============================================================================
# Main Function
# =============================================================================
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -r|--region)
                AWS_REGION="$2"
                shift 2
                ;;
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            --skip-terraform)
                SKIP_TERRAFORM="true"
                shift
                ;;
            --skip-docker-build)
                SKIP_DOCKER_BUILD="true"
                shift
                ;;
            --skip-monitoring)
                SKIP_MONITORING="true"
                shift
                ;;
            --force-recreate)
                FORCE_RECREATE="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --debug)
                DEBUG="true"
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Validate deployment mode
    if [[ ! "$DEPLOYMENT_MODE" =~ ^(docker-compose|kubernetes|both)$ ]]; then
        error "Invalid deployment mode: $DEPLOYMENT_MODE"
        error "Valid modes: docker-compose, kubernetes, both"
        exit 1
    fi
    
    # Set trap for cleanup on failure
    trap cleanup_on_failure ERR
    
    # Start deployment
    info "Starting Pat Fortress deployment..."
    info "Environment: $ENVIRONMENT"
    info "AWS Region: $AWS_REGION"
    info "Deployment Mode: $DEPLOYMENT_MODE"
    info "Version: $VERSION"
    info "Dry Run: $DRY_RUN"
    
    # Execute deployment steps
    check_prerequisites
    load_environment
    build_docker_images
    deploy_terraform
    deploy_kubernetes
    deploy_docker_compose
    deploy_monitoring
    run_post_deployment_tests
    generate_deployment_summary
    
    success "Pat Fortress deployment completed successfully!"
    success "Check the deployment summary above for access information."
}

# =============================================================================
# Execute Main Function
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi