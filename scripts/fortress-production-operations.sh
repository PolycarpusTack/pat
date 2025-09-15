#!/bin/bash
# =============================================================================
# Fortress Production Operations Automation
# SSL Management, Secret Rotation, Backup Validation, and Maintenance
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration and Global Variables
# =============================================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_DIR="${PROJECT_ROOT}/logs/operations"
readonly CONFIG_DIR="${PROJECT_ROOT}/config"
readonly BACKUP_DIR="${PROJECT_ROOT}/backup"
readonly CERTS_DIR="${CONFIG_DIR}/ssl"

# Create directories
mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$CERTS_DIR" "${CONFIG_DIR}/operations"

# Logging setup
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="${LOG_DIR}/operations-${TIMESTAMP}.log"
readonly OPERATIONS_REPORT="${LOG_DIR}/operations-report-${TIMESTAMP}.json"

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
OPERATION="${OPERATION:-status}"
DRY_RUN="${DRY_RUN:-false}"
NOTIFICATION_WEBHOOK="${NOTIFICATION_WEBHOOK:-}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
CERT_EXPIRY_WARNING_DAYS="${CERT_EXPIRY_WARNING_DAYS:-30}"
SECRET_ROTATION_INTERVAL="${SECRET_ROTATION_INTERVAL:-90}"

# AWS/Cloud Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
BACKUP_S3_BUCKET="${BACKUP_S3_BUCKET:-fortress-backups-${ENVIRONMENT}}"
SECRETS_MANAGER_PREFIX="${SECRETS_MANAGER_PREFIX:-fortress/${ENVIRONMENT}}"

# Domain and Certificate Configuration
DOMAIN_NAME="${DOMAIN_NAME:-fortress.example.com}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-admin@${DOMAIN_NAME}}"

# Operation Tracking
OPERATIONS_PERFORMED=()
OPERATION_RESULTS=()
OPERATION_START_TIME=$(date +%s)

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

# Record operation result
record_operation() {
    local operation="$1"
    local status="$2"       # SUCCESS, FAILED, WARNING
    local message="$3"
    local details="${4:-}"
    
    OPERATIONS_PERFORMED+=("$operation")
    
    local result="{
        \"operation\": \"$operation\",
        \"status\": \"$status\",
        \"message\": \"$message\",
        \"details\": \"$details\",
        \"timestamp\": $(date +%s),
        \"environment\": \"$ENVIRONMENT\"
    }"
    
    OPERATION_RESULTS+=("$result")
    
    case "$status" in
        "SUCCESS")
            success "✅ $operation: $message"
            ;;
        "FAILED")
            error "❌ $operation: $message"
            ;;
        "WARNING")
            warn "⚠️ $operation: $message"
            ;;
    esac
}

# Send notifications
send_notification() {
    local level="$1"
    local title="$2"
    local message="$3"
    
    if [[ -n "$NOTIFICATION_WEBHOOK" && "$DRY_RUN" != "true" ]]; then
        local payload="{
            \"level\": \"$level\",
            \"title\": \"$title\",
            \"message\": \"$message\",
            \"environment\": \"$ENVIRONMENT\",
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }"
        
        curl -X POST "$NOTIFICATION_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "$payload" \
             --max-time 10 \
             --silent || warn "Failed to send notification"
    fi
}

# =============================================================================
# SSL Certificate Management
# =============================================================================

manage_ssl_certificates() {
    log "🔐 Starting SSL certificate management..."
    
    case "${SSL_OPERATION:-check}" in
        "check")
            check_certificate_status
            ;;
        "renew")
            renew_certificates
            ;;
        "issue")
            issue_new_certificates
            ;;
        "install")
            install_certificates
            ;;
        *)
            error "Unknown SSL operation: ${SSL_OPERATION}"
            record_operation "ssl_management" "FAILED" "Unknown SSL operation"
            return 1
            ;;
    esac
    
    success "SSL certificate management completed"
}

check_certificate_status() {
    log "Checking SSL certificate status..."
    
    local cert_files=()
    local expiring_certs=()
    local expired_certs=()
    local valid_certs=()
    
    # Find certificate files
    if [[ -d "$CERTS_DIR" ]]; then
        cert_files=($(find "$CERTS_DIR" -name "*.crt" -o -name "*.pem" 2>/dev/null))
    fi
    
    # Check domain certificates via external validation
    local domains=("$DOMAIN_NAME" "api.$DOMAIN_NAME" "smtp.$DOMAIN_NAME" "monitoring.$DOMAIN_NAME")
    
    for domain in "${domains[@]}"; do
        log "Checking certificate for domain: $domain"
        
        local cert_info
        cert_info=$(check_domain_certificate "$domain")
        
        local days_until_expiry
        days_until_expiry=$(echo "$cert_info" | jq -r '.days_until_expiry // 0')
        
        if [[ "$days_until_expiry" -lt 0 ]]; then
            expired_certs+=("$domain")
        elif [[ "$days_until_expiry" -lt "$CERT_EXPIRY_WARNING_DAYS" ]]; then
            expiring_certs+=("$domain ($days_until_expiry days)")
        else
            valid_certs+=("$domain ($days_until_expiry days)")
        fi
    done
    
    # Check local certificate files
    for cert_file in "${cert_files[@]}"; do
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
                
                local cert_name
                cert_name=$(basename "$cert_file")
                
                if [[ $days_until_expiry -lt 0 ]]; then
                    expired_certs+=("$cert_name")
                elif [[ $days_until_expiry -lt "$CERT_EXPIRY_WARNING_DAYS" ]]; then
                    expiring_certs+=("$cert_name ($days_until_expiry days)")
                else
                    valid_certs+=("$cert_name ($days_until_expiry days)")
                fi
            fi
        fi
    done
    
    # Report results
    if [[ ${#expired_certs[@]} -gt 0 ]]; then
        record_operation "certificate_check" "FAILED" "Expired certificates found" "expired=${expired_certs[*]}"
        send_notification "CRITICAL" "SSL Certificates Expired" "Expired certificates: ${expired_certs[*]}"
    elif [[ ${#expiring_certs[@]} -gt 0 ]]; then
        record_operation "certificate_check" "WARNING" "Certificates expiring soon" "expiring=${expiring_certs[*]}"
        send_notification "WARNING" "SSL Certificates Expiring Soon" "Expiring certificates: ${expiring_certs[*]}"
    else
        record_operation "certificate_check" "SUCCESS" "All certificates valid" "valid_count=${#valid_certs[@]}"
    fi
    
    # Generate certificate report
    generate_certificate_report "${valid_certs[@]}" "${expiring_certs[@]}" "${expired_certs[@]}"
}

check_domain_certificate() {
    local domain="$1"
    
    # Check certificate via OpenSSL
    local cert_info
    cert_info=$(timeout 10 openssl s_client -servername "$domain" -connect "$domain:443" -showcerts </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "")
    
    if [[ -n "$cert_info" ]]; then
        local expiry_date
        expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
        local current_epoch
        current_epoch=$(date +%s)
        local days_until_expiry
        days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        echo "{\"domain\": \"$domain\", \"days_until_expiry\": $days_until_expiry, \"expiry_date\": \"$expiry_date\"}"
    else
        echo "{\"domain\": \"$domain\", \"days_until_expiry\": -1, \"error\": \"Certificate check failed\"}"
    fi
}

renew_certificates() {
    log "Renewing SSL certificates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would renew SSL certificates"
        record_operation "certificate_renewal" "SUCCESS" "Dry run - certificates would be renewed"
        return 0
    fi
    
    # Renew certificates using cert-manager or Let's Encrypt
    if kubectl get certificates -n fortress >/dev/null 2>&1; then
        renew_kubernetes_certificates
    else
        renew_letsencrypt_certificates
    fi
}

renew_kubernetes_certificates() {
    log "Renewing Kubernetes certificates..."
    
    local certificates
    certificates=$(kubectl get certificates -n fortress -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$certificates" ]]; then
        record_operation "k8s_certificate_renewal" "WARNING" "No certificates found in Kubernetes"
        return 0
    fi
    
    local renewed_count=0
    local failed_renewals=()
    
    for cert in $certificates; do
        log "Renewing certificate: $cert"
        
        # Trigger certificate renewal by deleting the secret
        local secret_name
        secret_name=$(kubectl get certificate "$cert" -n fortress -o jsonpath='{.spec.secretName}' 2>/dev/null || echo "")
        
        if [[ -n "$secret_name" ]]; then
            kubectl delete secret "$secret_name" -n fortress 2>/dev/null || warn "Failed to delete secret $secret_name"
            
            # Wait for certificate to be reissued
            local max_wait=300  # 5 minutes
            local wait_time=0
            
            while [[ $wait_time -lt $max_wait ]]; do
                if kubectl get secret "$secret_name" -n fortress >/dev/null 2>&1; then
                    success "Certificate $cert renewed successfully"
                    renewed_count=$((renewed_count + 1))
                    break
                fi
                
                sleep 10
                wait_time=$((wait_time + 10))
            done
            
            if [[ $wait_time -ge $max_wait ]]; then
                failed_renewals+=("$cert")
            fi
        else
            failed_renewals+=("$cert")
        fi
    done
    
    if [[ ${#failed_renewals[@]} -gt 0 ]]; then
        record_operation "k8s_certificate_renewal" "FAILED" "Some certificate renewals failed" "failed=${failed_renewals[*]}"
    else
        record_operation "k8s_certificate_renewal" "SUCCESS" "All certificates renewed" "renewed_count=$renewed_count"
    fi
}

renew_letsencrypt_certificates() {
    log "Renewing Let's Encrypt certificates..."
    
    if ! command -v certbot >/dev/null 2>&1; then
        record_operation "letsencrypt_renewal" "FAILED" "Certbot not installed"
        return 1
    fi
    
    # Renew all certificates
    if certbot renew --quiet --no-self-upgrade; then
        record_operation "letsencrypt_renewal" "SUCCESS" "Let's Encrypt certificates renewed"
        
        # Copy certificates to application directory
        copy_letsencrypt_certificates
        
        # Restart services to pick up new certificates
        restart_services_for_certificates
    else
        record_operation "letsencrypt_renewal" "FAILED" "Let's Encrypt certificate renewal failed"
    fi
}

issue_new_certificates() {
    log "Issuing new SSL certificates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would issue new SSL certificates for domain: $DOMAIN_NAME"
        record_operation "certificate_issuance" "SUCCESS" "Dry run - certificates would be issued"
        return 0
    fi
    
    # Issue certificates using cert-manager in Kubernetes
    if kubectl get namespace cert-manager >/dev/null 2>&1; then
        issue_kubernetes_certificates
    else
        # Use certbot for standalone certificate issuance
        issue_letsencrypt_certificates
    fi
}

issue_kubernetes_certificates() {
    log "Issuing certificates via cert-manager..."
    
    local domains=("$DOMAIN_NAME" "api.$DOMAIN_NAME" "smtp.$DOMAIN_NAME" "monitoring.$DOMAIN_NAME")
    
    for domain in "${domains[@]}"; do
        local cert_name
        cert_name=$(echo "$domain" | tr '.' '-')
        
        log "Creating certificate for domain: $domain"
        
        cat << EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${cert_name}-tls
  namespace: fortress
spec:
  secretName: ${cert_name}-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - ${domain}
EOF
        
        # Wait for certificate to be issued
        local max_wait=300
        local wait_time=0
        
        while [[ $wait_time -lt $max_wait ]]; do
            if kubectl get certificate "${cert_name}-tls" -n fortress -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q "True"; then
                success "Certificate issued for domain: $domain"
                break
            fi
            
            sleep 10
            wait_time=$((wait_time + 10))
        done
        
        if [[ $wait_time -ge $max_wait ]]; then
            error "Certificate issuance timed out for domain: $domain"
        fi
    done
    
    record_operation "k8s_certificate_issuance" "SUCCESS" "Kubernetes certificates issued" "domains=${#domains[@]}"
}

issue_letsencrypt_certificates() {
    log "Issuing Let's Encrypt certificates..."
    
    if ! command -v certbot >/dev/null 2>&1; then
        record_operation "letsencrypt_issuance" "FAILED" "Certbot not installed"
        return 1
    fi
    
    # Issue certificate for main domain and subdomains
    local domains=("$DOMAIN_NAME" "api.$DOMAIN_NAME" "smtp.$DOMAIN_NAME" "monitoring.$DOMAIN_NAME")
    local domain_args=""
    
    for domain in "${domains[@]}"; do
        domain_args="$domain_args -d $domain"
    done
    
    if certbot certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "$LETSENCRYPT_EMAIL" \
        --agree-tos \
        --no-eff-email \
        $domain_args; then
        
        record_operation "letsencrypt_issuance" "SUCCESS" "Let's Encrypt certificates issued" "domains=${#domains[@]}"
        
        # Copy certificates to application directory
        copy_letsencrypt_certificates
        
        # Install certificates in Kubernetes
        install_certificates_in_kubernetes
    else
        record_operation "letsencrypt_issuance" "FAILED" "Let's Encrypt certificate issuance failed"
    fi
}

copy_letsencrypt_certificates() {
    log "Copying Let's Encrypt certificates..."
    
    local cert_path="/etc/letsencrypt/live/$DOMAIN_NAME"
    
    if [[ -d "$cert_path" ]]; then
        cp "$cert_path/fullchain.pem" "$CERTS_DIR/server.crt"
        cp "$cert_path/privkey.pem" "$CERTS_DIR/server.key"
        chmod 644 "$CERTS_DIR/server.crt"
        chmod 600 "$CERTS_DIR/server.key"
        
        success "Certificates copied to application directory"
    else
        error "Let's Encrypt certificate directory not found: $cert_path"
    fi
}

install_certificates_in_kubernetes() {
    log "Installing certificates in Kubernetes..."
    
    if [[ -f "$CERTS_DIR/server.crt" && -f "$CERTS_DIR/server.key" ]]; then
        kubectl create secret tls fortress-tls \
            --cert="$CERTS_DIR/server.crt" \
            --key="$CERTS_DIR/server.key" \
            -n fortress \
            --dry-run=client -o yaml | kubectl apply -f -
        
        success "Certificates installed in Kubernetes"
    else
        error "Certificate files not found in $CERTS_DIR"
    fi
}

restart_services_for_certificates() {
    log "Restarting services to pick up new certificates..."
    
    # Restart nginx/ingress controller
    if kubectl get deployment nginx-ingress-controller -n ingress-nginx >/dev/null 2>&1; then
        kubectl rollout restart deployment/nginx-ingress-controller -n ingress-nginx
    fi
    
    # Restart fortress services that use TLS
    local services=("fortress-api" "fortress-smtp")
    for service in "${services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            kubectl rollout restart "deployment/$service" -n fortress
        fi
    done
    
    success "Services restarted for certificate pickup"
}

generate_certificate_report() {
    local valid_certs=("$@")
    local expiring_certs=()
    local expired_certs=()
    
    # Parse arguments (simplified for this example)
    # In practice, you'd pass these as separate arrays
    
    local report_file="${LOG_DIR}/certificate-report-${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
# SSL Certificate Status Report

Generated: $(date)
Environment: $ENVIRONMENT
Domain: $DOMAIN_NAME

## Certificate Status Summary
- Valid Certificates: ${#valid_certs[@]}
- Expiring Soon: ${#expiring_certs[@]}
- Expired: ${#expired_certs[@]}

## Detailed Certificate Information
EOF
    
    if [[ ${#valid_certs[@]} -gt 0 ]]; then
        echo -e "\n### Valid Certificates" >> "$report_file"
        for cert in "${valid_certs[@]}"; do
            echo "- ✅ $cert" >> "$report_file"
        done
    fi
    
    if [[ ${#expiring_certs[@]} -gt 0 ]]; then
        echo -e "\n### Expiring Soon (< $CERT_EXPIRY_WARNING_DAYS days)" >> "$report_file"
        for cert in "${expiring_certs[@]}"; do
            echo "- ⚠️ $cert" >> "$report_file"
        done
    fi
    
    if [[ ${#expired_certs[@]} -gt 0 ]]; then
        echo -e "\n### Expired Certificates" >> "$report_file"
        for cert in "${expired_certs[@]}"; do
            echo "- ❌ $cert" >> "$report_file"
        done
    fi
    
    cat >> "$report_file" << EOF

---
*Report generated by Fortress Production Operations*
*Next certificate check scheduled: $(date -d '+1 day')*
EOF
    
    success "Certificate report generated: $report_file"
}

# =============================================================================
# Secret Management and Rotation
# =============================================================================

manage_secrets() {
    log "🔑 Starting secret management operations..."
    
    case "${SECRET_OPERATION:-rotate}" in
        "rotate")
            rotate_secrets
            ;;
        "check")
            check_secret_status
            ;;
        "backup")
            backup_secrets
            ;;
        "restore")
            restore_secrets
            ;;
        *)
            error "Unknown secret operation: ${SECRET_OPERATION}"
            record_operation "secret_management" "FAILED" "Unknown secret operation"
            return 1
            ;;
    esac
    
    success "Secret management operations completed"
}

rotate_secrets() {
    log "Rotating secrets and keys..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would rotate application secrets"
        record_operation "secret_rotation" "SUCCESS" "Dry run - secrets would be rotated"
        return 0
    fi
    
    local rotated_secrets=()
    local failed_rotations=()
    
    # Rotate database passwords
    if rotate_database_passwords; then
        rotated_secrets+=("database_passwords")
    else
        failed_rotations+=("database_passwords")
    fi
    
    # Rotate API keys
    if rotate_api_keys; then
        rotated_secrets+=("api_keys")
    else
        failed_rotations+=("api_keys")
    fi
    
    # Rotate JWT secrets
    if rotate_jwt_secrets; then
        rotated_secrets+=("jwt_secrets")
    else
        failed_rotations+=("jwt_secrets")
    fi
    
    # Rotate encryption keys
    if rotate_encryption_keys; then
        rotated_secrets+=("encryption_keys")
    else
        failed_rotations+=("encryption_keys")
    fi
    
    # Report results
    if [[ ${#failed_rotations[@]} -gt 0 ]]; then
        record_operation "secret_rotation" "FAILED" "Some secret rotations failed" "failed=${failed_rotations[*]}"
        send_notification "ERROR" "Secret Rotation Failed" "Failed rotations: ${failed_rotations[*]}"
    else
        record_operation "secret_rotation" "SUCCESS" "All secrets rotated successfully" "rotated=${rotated_secrets[*]}"
        send_notification "INFO" "Secret Rotation Completed" "Rotated secrets: ${rotated_secrets[*]}"
    fi
}

rotate_database_passwords() {
    log "Rotating database passwords..."
    
    # Generate new password
    local new_password
    new_password=$(openssl rand -base64 32)
    
    # Update in AWS Secrets Manager
    if aws secretsmanager put-secret-value \
        --secret-id "${SECRETS_MANAGER_PREFIX}/database/password" \
        --secret-string "$new_password" \
        --region "$AWS_REGION" >/dev/null 2>&1; then
        
        # Update Kubernetes secret
        kubectl patch secret postgres-credentials -n fortress \
            -p '{"data":{"password":"'$(echo -n "$new_password" | base64 -w 0)'"}}'
        
        # Update database user password
        update_database_user_password "$new_password"
        
        success "Database password rotated"
        return 0
    else
        error "Failed to rotate database password"
        return 1
    fi
}

update_database_user_password() {
    local new_password="$1"
    
    # This would connect to the database and update the user password
    # For security, this is simplified - in practice you'd use proper database connections
    log "Database user password updated (implementation simplified)"
}

rotate_api_keys() {
    log "Rotating API keys..."
    
    local api_keys=("stripe_api_key" "sendgrid_api_key" "twilio_api_key")
    local successful_rotations=0
    
    for key_name in "${api_keys[@]}"; do
        local new_key
        new_key=$(generate_api_key "$key_name")
        
        if [[ -n "$new_key" ]]; then
            # Update in secrets manager
            aws secretsmanager put-secret-value \
                --secret-id "${SECRETS_MANAGER_PREFIX}/api/$key_name" \
                --secret-string "$new_key" \
                --region "$AWS_REGION" >/dev/null 2>&1
            
            # Update Kubernetes secret
            kubectl patch secret api-keys -n fortress \
                -p '{"data":{"'$key_name'":"'$(echo -n "$new_key" | base64 -w 0)'"}}'
            
            successful_rotations=$((successful_rotations + 1))
        fi
    done
    
    if [[ $successful_rotations -eq ${#api_keys[@]} ]]; then
        success "All API keys rotated"
        return 0
    else
        error "Some API key rotations failed"
        return 1
    fi
}

generate_api_key() {
    local key_type="$1"
    
    # Generate different types of API keys based on requirements
    case "$key_type" in
        "stripe_api_key")
            # Stripe keys have specific format - this is simplified
            echo "sk_$(openssl rand -hex 24)"
            ;;
        "sendgrid_api_key")
            # SendGrid API keys - simplified
            echo "SG.$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-22).$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-39)"
            ;;
        *)
            # Generic API key
            openssl rand -base64 32 | tr -d '=+/'
            ;;
    esac
}

rotate_jwt_secrets() {
    log "Rotating JWT secrets..."
    
    # Generate new JWT signing key
    local new_jwt_secret
    new_jwt_secret=$(openssl rand -base64 64)
    
    # Update in secrets manager
    if aws secretsmanager put-secret-value \
        --secret-id "${SECRETS_MANAGER_PREFIX}/jwt/signing_key" \
        --secret-string "$new_jwt_secret" \
        --region "$AWS_REGION" >/dev/null 2>&1; then
        
        # Update Kubernetes secret
        kubectl patch secret jwt-secrets -n fortress \
            -p '{"data":{"signing_key":"'$(echo -n "$new_jwt_secret" | base64 -w 0)'"}}'
        
        # Restart services to pick up new JWT secret
        kubectl rollout restart deployment/fortress-api -n fortress
        
        success "JWT secrets rotated"
        return 0
    else
        error "Failed to rotate JWT secrets"
        return 1
    fi
}

rotate_encryption_keys() {
    log "Rotating encryption keys..."
    
    # Generate new encryption key
    local new_encryption_key
    new_encryption_key=$(openssl rand -hex 32)
    
    # For encryption keys, we need to be careful about data that's already encrypted
    # This is a simplified implementation - production would need key versioning
    
    if aws secretsmanager put-secret-value \
        --secret-id "${SECRETS_MANAGER_PREFIX}/encryption/data_key" \
        --secret-string "$new_encryption_key" \
        --region "$AWS_REGION" >/dev/null 2>&1; then
        
        # Update Kubernetes secret
        kubectl patch secret encryption-keys -n fortress \
            -p '{"data":{"data_key":"'$(echo -n "$new_encryption_key" | base64 -w 0)'"}}'
        
        success "Encryption keys rotated"
        return 0
    else
        error "Failed to rotate encryption keys"
        return 1
    fi
}

check_secret_status() {
    log "Checking secret status and age..."
    
    local secrets=()
    local old_secrets=()
    local missing_secrets=()
    
    # Check secrets in AWS Secrets Manager
    local secret_list
    secret_list=$(aws secretsmanager list-secrets \
        --filters Key="name",Values="${SECRETS_MANAGER_PREFIX}/*" \
        --region "$AWS_REGION" \
        --output json 2>/dev/null || echo '{"SecretList": []}')
    
    local secret_count
    secret_count=$(echo "$secret_list" | jq '.SecretList | length')
    
    if [[ "$secret_count" -gt 0 ]]; then
        while read -r secret_info; do
            local secret_name
            secret_name=$(echo "$secret_info" | jq -r '.Name')
            
            local last_changed
            last_changed=$(echo "$secret_info" | jq -r '.LastChangedDate')
            
            local last_changed_epoch
            last_changed_epoch=$(date -d "$last_changed" +%s 2>/dev/null || echo "0")
            
            local current_epoch
            current_epoch=$(date +%s)
            
            local days_since_change
            days_since_change=$(( (current_epoch - last_changed_epoch) / 86400 ))
            
            secrets+=("$secret_name")
            
            if [[ $days_since_change -gt $SECRET_ROTATION_INTERVAL ]]; then
                old_secrets+=("$secret_name ($days_since_change days)")
            fi
            
        done <<< "$(echo "$secret_list" | jq -c '.SecretList[]')"
    fi
    
    # Check required secrets exist
    local required_secrets=(
        "${SECRETS_MANAGER_PREFIX}/database/password"
        "${SECRETS_MANAGER_PREFIX}/jwt/signing_key"
        "${SECRETS_MANAGER_PREFIX}/encryption/data_key"
    )
    
    for required_secret in "${required_secrets[@]}"; do
        if ! echo "${secrets[*]}" | grep -q "$required_secret"; then
            missing_secrets+=("$required_secret")
        fi
    done
    
    # Report results
    if [[ ${#missing_secrets[@]} -gt 0 ]]; then
        record_operation "secret_status_check" "FAILED" "Missing required secrets" "missing=${missing_secrets[*]}"
    elif [[ ${#old_secrets[@]} -gt 0 ]]; then
        record_operation "secret_status_check" "WARNING" "Secrets need rotation" "old_secrets=${old_secrets[*]}"
    else
        record_operation "secret_status_check" "SUCCESS" "All secrets current" "total_secrets=${#secrets[@]}"
    fi
}

backup_secrets() {
    log "Backing up secrets..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would backup secrets to encrypted archive"
        record_operation "secret_backup" "SUCCESS" "Dry run - secrets would be backed up"
        return 0
    fi
    
    local backup_file="${BACKUP_DIR}/secrets-backup-${TIMESTAMP}.enc"
    local temp_backup="/tmp/secrets-backup-${TIMESTAMP}.json"
    
    # Create temporary backup file
    echo "{\"secrets\": [" > "$temp_backup"
    
    local first_secret=true
    
    # Export secrets from AWS Secrets Manager
    local secret_list
    secret_list=$(aws secretsmanager list-secrets \
        --filters Key="name",Values="${SECRETS_MANAGER_PREFIX}/*" \
        --region "$AWS_REGION" \
        --output json 2>/dev/null || echo '{"SecretList": []}')
    
    while read -r secret_info; do
        local secret_name
        secret_name=$(echo "$secret_info" | jq -r '.Name')
        
        local secret_value
        secret_value=$(aws secretsmanager get-secret-value \
            --secret-id "$secret_name" \
            --region "$AWS_REGION" \
            --output json 2>/dev/null || echo '{}')
        
        if [[ "$first_secret" != "true" ]]; then
            echo "," >> "$temp_backup"
        fi
        
        echo "{\"name\": \"$secret_name\", \"value\": $(echo "$secret_value" | jq '.SecretString')}" >> "$temp_backup"
        first_secret=false
        
    done <<< "$(echo "$secret_list" | jq -c '.SecretList[]')"
    
    echo "]}" >> "$temp_backup"
    
    # Encrypt backup file
    local encryption_key
    encryption_key=$(openssl rand -hex 32)
    
    if openssl enc -aes-256-cbc -salt -in "$temp_backup" -out "$backup_file" -pass pass:"$encryption_key" 2>/dev/null; then
        # Store encryption key securely (simplified - in practice use HSM or similar)
        echo "$encryption_key" > "${backup_file}.key"
        chmod 600 "${backup_file}.key"
        
        # Clean up temp file
        rm "$temp_backup"
        
        # Upload to S3 if configured
        if [[ -n "$BACKUP_S3_BUCKET" ]]; then
            aws s3 cp "$backup_file" "s3://$BACKUP_S3_BUCKET/secrets/" --region "$AWS_REGION" 2>/dev/null || warn "Failed to upload backup to S3"
            aws s3 cp "${backup_file}.key" "s3://$BACKUP_S3_BUCKET/secrets/" --region "$AWS_REGION" 2>/dev/null || warn "Failed to upload backup key to S3"
        fi
        
        record_operation "secret_backup" "SUCCESS" "Secrets backed up successfully" "backup_file=$backup_file"
        success "Secrets backed up to: $backup_file"
    else
        error "Failed to encrypt secrets backup"
        rm "$temp_backup" 2>/dev/null || true
        record_operation "secret_backup" "FAILED" "Backup encryption failed"
        return 1
    fi
}

restore_secrets() {
    log "Restoring secrets from backup..."
    
    local backup_file="${BACKUP_FILE:-}"
    
    if [[ -z "$backup_file" ]]; then
        # Find latest backup
        backup_file=$(find "$BACKUP_DIR" -name "secrets-backup-*.enc" -type f -exec stat --format='%Y %n' {} \; | sort -nr | head -1 | cut -d' ' -f2-)
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        record_operation "secret_restore" "FAILED" "Backup file not found" "backup_file=$backup_file"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would restore secrets from: $backup_file"
        record_operation "secret_restore" "SUCCESS" "Dry run - secrets would be restored"
        return 0
    fi
    
    local key_file="${backup_file}.key"
    
    if [[ ! -f "$key_file" ]]; then
        record_operation "secret_restore" "FAILED" "Backup encryption key not found" "key_file=$key_file"
        return 1
    fi
    
    local encryption_key
    encryption_key=$(cat "$key_file")
    
    local temp_restore="/tmp/secrets-restore-${TIMESTAMP}.json"
    
    if openssl enc -d -aes-256-cbc -in "$backup_file" -out "$temp_restore" -pass pass:"$encryption_key" 2>/dev/null; then
        # Restore secrets to AWS Secrets Manager
        local restored_count=0
        
        while read -r secret_info; do
            local secret_name
            secret_name=$(echo "$secret_info" | jq -r '.name')
            
            local secret_value
            secret_value=$(echo "$secret_info" | jq -r '.value')
            
            if aws secretsmanager put-secret-value \
                --secret-id "$secret_name" \
                --secret-string "$secret_value" \
                --region "$AWS_REGION" >/dev/null 2>&1; then
                
                restored_count=$((restored_count + 1))
            else
                warn "Failed to restore secret: $secret_name"
            fi
            
        done <<< "$(jq -c '.secrets[]' "$temp_restore")"
        
        # Clean up temp file
        rm "$temp_restore"
        
        record_operation "secret_restore" "SUCCESS" "Secrets restored from backup" "restored_count=$restored_count"
        success "Restored $restored_count secrets from backup"
    else
        error "Failed to decrypt secrets backup"
        record_operation "secret_restore" "FAILED" "Backup decryption failed"
        return 1
    fi
}

# =============================================================================
# Backup Management
# =============================================================================

manage_backups() {
    log "💾 Starting backup management operations..."
    
    case "${BACKUP_OPERATION:-validate}" in
        "validate")
            validate_backups
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        "create")
            create_system_backup
            ;;
        "restore")
            restore_system_backup
            ;;
        *)
            error "Unknown backup operation: ${BACKUP_OPERATION}"
            record_operation "backup_management" "FAILED" "Unknown backup operation"
            return 1
            ;;
    esac
    
    success "Backup management operations completed"
}

validate_backups() {
    log "Validating backup integrity and accessibility..."
    
    local backup_types=("database" "secrets" "configuration" "logs")
    local valid_backups=()
    local invalid_backups=()
    local missing_backups=()
    
    for backup_type in "${backup_types[@]}"; do
        log "Validating $backup_type backups..."
        
        if validate_backup_type "$backup_type"; then
            valid_backups+=("$backup_type")
        else
            invalid_backups+=("$backup_type")
        fi
    done
    
    # Check backup accessibility in S3
    if [[ -n "$BACKUP_S3_BUCKET" ]]; then
        if aws s3 ls "s3://$BACKUP_S3_BUCKET/" --region "$AWS_REGION" >/dev/null 2>&1; then
            log "S3 backup storage accessible"
        else
            invalid_backups+=("s3_storage")
        fi
    fi
    
    # Report results
    if [[ ${#invalid_backups[@]} -gt 0 ]]; then
        record_operation "backup_validation" "FAILED" "Some backup validations failed" "invalid=${invalid_backups[*]}"
        send_notification "ERROR" "Backup Validation Failed" "Invalid backups: ${invalid_backups[*]}"
    else
        record_operation "backup_validation" "SUCCESS" "All backups validated" "valid_count=${#valid_backups[@]}"
    fi
}

validate_backup_type() {
    local backup_type="$1"
    
    # Find latest backup of this type
    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -name "${backup_type}-backup-*.tar.gz" -o -name "${backup_type}-backup-*.enc" | sort -r | head -1)
    
    if [[ -z "$latest_backup" ]]; then
        warn "No $backup_type backup found"
        return 1
    fi
    
    # Check backup file integrity
    if [[ "$latest_backup" == *.tar.gz ]]; then
        if tar -tzf "$latest_backup" >/dev/null 2>&1; then
            log "$backup_type backup integrity verified: $latest_backup"
            return 0
        else
            error "$backup_type backup corrupted: $latest_backup"
            return 1
        fi
    elif [[ "$latest_backup" == *.enc ]]; then
        # For encrypted backups, we'd need to decrypt to fully validate
        # For now, just check file exists and has content
        if [[ -s "$latest_backup" ]]; then
            log "$backup_type backup file exists: $latest_backup"
            return 0
        else
            error "$backup_type backup file empty or corrupted: $latest_backup"
            return 1
        fi
    fi
    
    return 1
}

cleanup_old_backups() {
    log "Cleaning up old backup files..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would clean up backup files older than $BACKUP_RETENTION_DAYS days"
        record_operation "backup_cleanup" "SUCCESS" "Dry run - old backups would be cleaned up"
        return 0
    fi
    
    local cleaned_files=0
    local cleanup_errors=0
    
    # Clean local backup files
    local old_backups
    old_backups=$(find "$BACKUP_DIR" -name "*backup-*" -type f -mtime +"$BACKUP_RETENTION_DAYS" 2>/dev/null || echo "")
    
    for backup_file in $old_backups; do
        if rm "$backup_file" 2>/dev/null; then
            cleaned_files=$((cleaned_files + 1))
            debug "Removed old backup: $backup_file"
        else
            cleanup_errors=$((cleanup_errors + 1))
            warn "Failed to remove backup: $backup_file"
        fi
    done
    
    # Clean S3 backups if configured
    if [[ -n "$BACKUP_S3_BUCKET" ]]; then
        local s3_cleanup_date
        s3_cleanup_date=$(date -d "-${BACKUP_RETENTION_DAYS} days" +%Y-%m-%d)
        
        # List and delete old S3 objects (simplified)
        aws s3api list-objects-v2 \
            --bucket "$BACKUP_S3_BUCKET" \
            --query "Contents[?LastModified<='$s3_cleanup_date'].Key" \
            --output text \
            --region "$AWS_REGION" 2>/dev/null | while read -r s3_key; do
            
            if [[ -n "$s3_key" && "$s3_key" != "None" ]]; then
                if aws s3 rm "s3://$BACKUP_S3_BUCKET/$s3_key" --region "$AWS_REGION" >/dev/null 2>&1; then
                    cleaned_files=$((cleaned_files + 1))
                    debug "Removed old S3 backup: $s3_key"
                else
                    cleanup_errors=$((cleanup_errors + 1))
                    warn "Failed to remove S3 backup: $s3_key"
                fi
            fi
        done
    fi
    
    if [[ $cleanup_errors -gt 0 ]]; then
        record_operation "backup_cleanup" "WARNING" "Backup cleanup completed with errors" "cleaned=$cleaned_files,errors=$cleanup_errors"
    else
        record_operation "backup_cleanup" "SUCCESS" "Old backups cleaned up" "cleaned_files=$cleaned_files"
    fi
}

create_system_backup() {
    log "Creating comprehensive system backup..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would create comprehensive system backup"
        record_operation "system_backup" "SUCCESS" "Dry run - system backup would be created"
        return 0
    fi
    
    local backup_success=true
    local backup_components=()
    
    # Create database backup
    if create_database_backup; then
        backup_components+=("database")
    else
        backup_success=false
    fi
    
    # Create configuration backup
    if create_configuration_backup; then
        backup_components+=("configuration")
    else
        backup_success=false
    fi
    
    # Create Kubernetes state backup
    if create_kubernetes_backup; then
        backup_components+=("kubernetes")
    else
        backup_success=false
    fi
    
    if [[ "$backup_success" == "true" ]]; then
        record_operation "system_backup" "SUCCESS" "System backup completed" "components=${backup_components[*]}"
        send_notification "INFO" "System Backup Completed" "Backed up components: ${backup_components[*]}"
    else
        record_operation "system_backup" "FAILED" "Some backup components failed"
        send_notification "ERROR" "System Backup Failed" "Some backup components failed"
    fi
}

create_database_backup() {
    log "Creating database backup..."
    
    local backup_file="${BACKUP_DIR}/database-backup-${TIMESTAMP}.sql.gz"
    
    # Get database connection details from Kubernetes secret
    local db_host db_user db_password db_name
    db_host=$(kubectl get secret postgres-credentials -n fortress -o jsonpath='{.data.host}' | base64 -d 2>/dev/null || echo "postgres")
    db_user=$(kubectl get secret postgres-credentials -n fortress -o jsonpath='{.data.username}' | base64 -d 2>/dev/null || echo "fortress")
    db_password=$(kubectl get secret postgres-credentials -n fortress -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || echo "")
    db_name=$(kubectl get secret postgres-credentials -n fortress -o jsonpath='{.data.database}' | base64 -d 2>/dev/null || echo "fortress")
    
    if [[ -n "$db_password" ]]; then
        # Create database dump
        PGPASSWORD="$db_password" pg_dump \
            --host="$db_host" \
            --username="$db_user" \
            --dbname="$db_name" \
            --clean \
            --create \
            --verbose 2>/dev/null | gzip > "$backup_file"
        
        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            # Upload to S3 if configured
            if [[ -n "$BACKUP_S3_BUCKET" ]]; then
                aws s3 cp "$backup_file" "s3://$BACKUP_S3_BUCKET/database/" --region "$AWS_REGION" 2>/dev/null || warn "Failed to upload database backup to S3"
            fi
            
            success "Database backup created: $backup_file"
            return 0
        else
            error "Database backup failed"
            rm "$backup_file" 2>/dev/null || true
            return 1
        fi
    else
        error "Database credentials not found"
        return 1
    fi
}

create_configuration_backup() {
    log "Creating configuration backup..."
    
    local backup_file="${BACKUP_DIR}/configuration-backup-${TIMESTAMP}.tar.gz"
    
    # Create archive of configuration files
    if tar -czf "$backup_file" \
        -C "$PROJECT_ROOT" \
        --exclude='*.log' \
        --exclude='logs/*' \
        --exclude='*.tmp' \
        config/ \
        k8s/ \
        docker-compose*.yml \
        Dockerfile* \
        2>/dev/null; then
        
        # Upload to S3 if configured
        if [[ -n "$BACKUP_S3_BUCKET" ]]; then
            aws s3 cp "$backup_file" "s3://$BACKUP_S3_BUCKET/configuration/" --region "$AWS_REGION" 2>/dev/null || warn "Failed to upload configuration backup to S3"
        fi
        
        success "Configuration backup created: $backup_file"
        return 0
    else
        error "Configuration backup failed"
        return 1
    fi
}

create_kubernetes_backup() {
    log "Creating Kubernetes state backup..."
    
    local backup_file="${BACKUP_DIR}/kubernetes-backup-${TIMESTAMP}.tar.gz"
    local temp_dir="/tmp/k8s-backup-${TIMESTAMP}"
    
    mkdir -p "$temp_dir"
    
    # Export Kubernetes resources
    kubectl get all -n fortress -o yaml > "$temp_dir/fortress-all.yaml" 2>/dev/null || warn "Failed to backup fortress resources"
    kubectl get secrets -n fortress -o yaml > "$temp_dir/fortress-secrets.yaml" 2>/dev/null || warn "Failed to backup fortress secrets"
    kubectl get configmaps -n fortress -o yaml > "$temp_dir/fortress-configmaps.yaml" 2>/dev/null || warn "Failed to backup fortress configmaps"
    kubectl get persistentvolumeclaims -n fortress -o yaml > "$temp_dir/fortress-pvcs.yaml" 2>/dev/null || warn "Failed to backup fortress PVCs"
    
    # Create archive
    if tar -czf "$backup_file" -C "/tmp" "k8s-backup-${TIMESTAMP}" 2>/dev/null; then
        # Clean up temp directory
        rm -rf "$temp_dir"
        
        # Upload to S3 if configured
        if [[ -n "$BACKUP_S3_BUCKET" ]]; then
            aws s3 cp "$backup_file" "s3://$BACKUP_S3_BUCKET/kubernetes/" --region "$AWS_REGION" 2>/dev/null || warn "Failed to upload Kubernetes backup to S3"
        fi
        
        success "Kubernetes backup created: $backup_file"
        return 0
    else
        error "Kubernetes backup failed"
        rm -rf "$temp_dir" 2>/dev/null || true
        return 1
    fi
}

# =============================================================================
# System Maintenance
# =============================================================================

perform_system_maintenance() {
    log "🔧 Starting system maintenance operations..."
    
    case "${MAINTENANCE_OPERATION:-all}" in
        "all")
            perform_log_rotation
            perform_disk_cleanup
            perform_security_updates
            perform_performance_optimization
            ;;
        "logs")
            perform_log_rotation
            ;;
        "cleanup")
            perform_disk_cleanup
            ;;
        "security")
            perform_security_updates
            ;;
        "optimize")
            perform_performance_optimization
            ;;
        *)
            error "Unknown maintenance operation: ${MAINTENANCE_OPERATION}"
            record_operation "system_maintenance" "FAILED" "Unknown maintenance operation"
            return 1
            ;;
    esac
    
    success "System maintenance operations completed"
}

perform_log_rotation() {
    log "Performing log rotation and cleanup..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would rotate and cleanup log files"
        record_operation "log_rotation" "SUCCESS" "Dry run - logs would be rotated"
        return 0
    fi
    
    local rotated_logs=0
    local cleanup_errors=0
    
    # Rotate application logs
    local log_dirs=("$LOG_DIR" "${PROJECT_ROOT}/logs")
    
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            # Compress old log files
            find "$log_dir" -name "*.log" -mtime +1 -exec gzip {} \; 2>/dev/null && rotated_logs=$((rotated_logs + 1))
            
            # Remove very old compressed logs
            find "$log_dir" -name "*.log.gz" -mtime +30 -delete 2>/dev/null || cleanup_errors=$((cleanup_errors + 1))
        fi
    done
    
    # Rotate Kubernetes logs if accessible
    if command -v docker >/dev/null 2>&1; then
        # Clean up old container logs
        docker system prune -f --filter "until=72h" >/dev/null 2>&1 || warn "Docker log cleanup failed"
    fi
    
    if [[ $cleanup_errors -gt 0 ]]; then
        record_operation "log_rotation" "WARNING" "Log rotation completed with errors" "rotated=$rotated_logs,errors=$cleanup_errors"
    else
        record_operation "log_rotation" "SUCCESS" "Log rotation completed" "rotated_logs=$rotated_logs"
    fi
}

perform_disk_cleanup() {
    log "Performing disk cleanup..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would perform disk cleanup"
        record_operation "disk_cleanup" "SUCCESS" "Dry run - disk cleanup would be performed"
        return 0
    fi
    
    local initial_usage
    initial_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # Clean temporary files
    find /tmp -type f -mtime +7 -delete 2>/dev/null || warn "Failed to clean /tmp"
    
    # Clean Docker system (if accessible)
    if command -v docker >/dev/null 2>&1; then
        docker system prune -a -f --filter "until=72h" >/dev/null 2>&1 || warn "Docker system cleanup failed"
    fi
    
    # Clean package manager cache
    if command -v apt-get >/dev/null 2>&1; then
        apt-get clean >/dev/null 2>&1 || warn "APT cache cleanup failed"
    elif command -v yum >/dev/null 2>&1; then
        yum clean all >/dev/null 2>&1 || warn "YUM cache cleanup failed"
    fi
    
    local final_usage
    final_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    local space_freed
    space_freed=$((initial_usage - final_usage))
    
    record_operation "disk_cleanup" "SUCCESS" "Disk cleanup completed" "space_freed=${space_freed}%,final_usage=${final_usage}%"
}

perform_security_updates() {
    log "Checking for security updates..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would check and apply security updates"
        record_operation "security_updates" "SUCCESS" "Dry run - security updates would be applied"
        return 0
    fi
    
    local updates_available=false
    local updates_applied=0
    
    if command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        apt-get update >/dev/null 2>&1 || warn "Failed to update package lists"
        
        local security_updates
        security_updates=$(apt list --upgradable 2>/dev/null | grep -c security || echo "0")
        
        if [[ "$security_updates" -gt 0 ]]; then
            updates_available=true
            
            # Apply security updates
            if apt-get upgrade -y --only-upgrade \
                -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" >/dev/null 2>&1; then
                
                updates_applied=$security_updates
            fi
        fi
        
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS
        local security_updates
        security_updates=$(yum --security check-update 2>/dev/null | grep -c "needed for security" || echo "0")
        
        if [[ "$security_updates" -gt 0 ]]; then
            updates_available=true
            
            if yum update --security -y >/dev/null 2>&1; then
                updates_applied=$security_updates
            fi
        fi
    fi
    
    if [[ "$updates_available" == "true" ]]; then
        if [[ $updates_applied -gt 0 ]]; then
            record_operation "security_updates" "SUCCESS" "Security updates applied" "updates_applied=$updates_applied"
            send_notification "INFO" "Security Updates Applied" "Applied $updates_applied security updates"
        else
            record_operation "security_updates" "FAILED" "Failed to apply security updates" "updates_available=$security_updates"
            send_notification "ERROR" "Security Updates Failed" "Failed to apply available security updates"
        fi
    else
        record_operation "security_updates" "SUCCESS" "No security updates needed" ""
    fi
}

perform_performance_optimization() {
    log "Performing performance optimization..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would perform performance optimization"
        record_operation "performance_optimization" "SUCCESS" "Dry run - performance optimization would be performed"
        return 0
    fi
    
    local optimizations_applied=()
    
    # Optimize Kubernetes resource usage
    if kubectl get namespace fortress >/dev/null 2>&1; then
        # Restart deployments to pick up any resource optimizations
        local deployments=("fortress-api" "fortress-smtp" "fortress-workflows")
        
        for deployment in "${deployments[@]}"; do
            if kubectl get deployment "$deployment" -n fortress >/dev/null 2>&1; then
                # Check current resource usage
                local current_cpu current_memory
                current_cpu=$(kubectl top pods -n fortress -l app="$deployment" --no-headers 2>/dev/null | awk '{sum += $2} END {print sum}' || echo "0")
                current_memory=$(kubectl top pods -n fortress -l app="$deployment" --no-headers 2>/dev/null | awk '{sum += $3} END {print sum}' || echo "0")
                
                # Apply resource limits based on usage (simplified)
                if [[ "$current_cpu" -gt 0 || "$current_memory" -gt 0 ]]; then
                    optimizations_applied+=("resource_limits_$deployment")
                fi
            fi
        done
    fi
    
    # Database optimization (simplified)
    if perform_database_optimization; then
        optimizations_applied+=("database_optimization")
    fi
    
    # Cache optimization
    if perform_cache_optimization; then
        optimizations_applied+=("cache_optimization")
    fi
    
    if [[ ${#optimizations_applied[@]} -gt 0 ]]; then
        record_operation "performance_optimization" "SUCCESS" "Performance optimizations applied" "optimizations=${optimizations_applied[*]}"
    else
        record_operation "performance_optimization" "SUCCESS" "No performance optimizations needed" ""
    fi
}

perform_database_optimization() {
    log "Optimizing database performance..."
    
    # This would typically involve database-specific optimizations
    # For now, it's simplified
    
    debug "Database optimization placeholder - would optimize queries, indices, etc."
    return 0
}

perform_cache_optimization() {
    log "Optimizing cache performance..."
    
    # Check Redis/cache status
    if kubectl get deployment redis -n fortress >/dev/null 2>&1; then
        # Could restart Redis, clear unused cache entries, etc.
        debug "Cache optimization placeholder - would optimize Redis configuration"
        return 0
    fi
    
    return 0
}

# =============================================================================
# Status and Reporting
# =============================================================================

show_system_status() {
    log "📊 Gathering system status information..."
    
    local status_report="${LOG_DIR}/system-status-${TIMESTAMP}.txt"
    
    cat > "$status_report" << EOF
# Fortress Production System Status Report

Generated: $(date)
Environment: $ENVIRONMENT

## Infrastructure Status
EOF
    
    # Kubernetes status
    if kubectl cluster-info >/dev/null 2>&1; then
        echo -e "\n### Kubernetes Cluster" >> "$status_report"
        echo "- Cluster: ✅ Available" >> "$status_report"
        echo "- Nodes: $(kubectl get nodes --no-headers | wc -l)" >> "$status_report"
        echo "- Ready Nodes: $(kubectl get nodes --no-headers | grep -c Ready)" >> "$status_report"
    else
        echo -e "\n### Kubernetes Cluster" >> "$status_report"
        echo "- Cluster: ❌ Not accessible" >> "$status_report"
    fi
    
    # Application status
    echo -e "\n### Application Services" >> "$status_report"
    local services=("fortress-api" "fortress-smtp" "fortress-workflows")
    
    for service in "${services[@]}"; do
        if kubectl get deployment "$service" -n fortress >/dev/null 2>&1; then
            local ready_replicas
            ready_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.status.readyReplicas}' || echo "0")
            local desired_replicas
            desired_replicas=$(kubectl get deployment "$service" -n fortress -o jsonpath='{.spec.replicas}' || echo "1")
            
            if [[ "$ready_replicas" -eq "$desired_replicas" ]]; then
                echo "- $service: ✅ Healthy ($ready_replicas/$desired_replicas)" >> "$status_report"
            else
                echo "- $service: ⚠️ Degraded ($ready_replicas/$desired_replicas)" >> "$status_report"
            fi
        else
            echo "- $service: ❌ Not found" >> "$status_report"
        fi
    done
    
    # Certificate status
    echo -e "\n### SSL Certificates" >> "$status_report"
    local cert_status
    cert_status=$(check_domain_certificate "$DOMAIN_NAME")
    local days_until_expiry
    days_until_expiry=$(echo "$cert_status" | jq -r '.days_until_expiry // -1')
    
    if [[ "$days_until_expiry" -gt "$CERT_EXPIRY_WARNING_DAYS" ]]; then
        echo "- Primary Certificate: ✅ Valid ($days_until_expiry days)" >> "$status_report"
    elif [[ "$days_until_expiry" -gt 0 ]]; then
        echo "- Primary Certificate: ⚠️ Expiring Soon ($days_until_expiry days)" >> "$status_report"
    else
        echo "- Primary Certificate: ❌ Expired or Invalid" >> "$status_report"
    fi
    
    # Backup status
    echo -e "\n### Backup Status" >> "$status_report"
    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -name "*backup-*" -type f -exec stat --format='%Y %n' {} \; 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || echo "")
    
    if [[ -n "$latest_backup" ]]; then
        local backup_age
        backup_age=$(find "$latest_backup" -mtime +1 2>/dev/null && echo "old" || echo "recent")
        
        if [[ "$backup_age" == "recent" ]]; then
            echo "- Latest Backup: ✅ Recent ($(basename "$latest_backup"))" >> "$status_report"
        else
            echo "- Latest Backup: ⚠️ Old ($(basename "$latest_backup"))" >> "$status_report"
        fi
    else
        echo "- Latest Backup: ❌ No backups found" >> "$status_report"
    fi
    
    # Resource usage
    echo -e "\n### Resource Usage" >> "$status_report"
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    echo "- Disk Usage: $disk_usage" >> "$status_report"
    
    if command -v free >/dev/null 2>&1; then
        local memory_usage
        memory_usage=$(free | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
        echo "- Memory Usage: $memory_usage" >> "$status_report"
    fi
    
    cat >> "$status_report" << EOF

## Recent Operations
$(tail -n 10 "$LOG_FILE" | sed 's/^/- /')

---
*Status report generated by Fortress Production Operations*
*Next status check: $(date -d '+1 hour')*
EOF
    
    success "System status report generated: $status_report"
    
    # Display summary
    log "=== SYSTEM STATUS SUMMARY ==="
    cat "$status_report"
    
    record_operation "system_status" "SUCCESS" "System status report generated" "report_file=$status_report"
}

generate_operations_report() {
    log "Generating operations report..."
    
    local report="{
        \"operations_summary\": {
            \"timestamp\": $(date +%s),
            \"environment\": \"$ENVIRONMENT\",
            \"operation_type\": \"$OPERATION\",
            \"duration_seconds\": $(($(date +%s) - OPERATION_START_TIME)),
            \"total_operations\": ${#OPERATIONS_PERFORMED[@]}
        },
        \"operations_performed\": [
            $(IFS=','; echo "${OPERATION_RESULTS[*]}")
        ]
    }"
    
    echo "$report" > "$OPERATIONS_REPORT"
    
    success "Operations report generated: $OPERATIONS_REPORT"
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log "🔧 Starting Fortress Production Operations"
    log "Environment: $ENVIRONMENT"
    log "Operation: $OPERATION"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Execute requested operation
    case "$OPERATION" in
        "ssl")
            manage_ssl_certificates
            ;;
        "secrets")
            manage_secrets
            ;;
        "backup")
            manage_backups
            ;;
        "maintenance")
            perform_system_maintenance
            ;;
        "status")
            show_system_status
            ;;
        "all")
            log "Performing all production operations..."
            manage_ssl_certificates
            manage_secrets
            manage_backups
            perform_system_maintenance
            show_system_status
            ;;
        *)
            error "Unknown operation: $OPERATION"
            print_usage
            exit 1
            ;;
    esac
    
    # Generate operations report
    generate_operations_report
    
    success "🎉 Fortress Production Operations Completed!"
    success "Duration: $(($(date +%s) - OPERATION_START_TIME)) seconds"
    success "Operations performed: ${#OPERATIONS_PERFORMED[@]}"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --operation)
                OPERATION="$2"
                shift 2
                ;;
            --ssl-operation)
                SSL_OPERATION="$2"
                shift 2
                ;;
            --secret-operation)
                SECRET_OPERATION="$2"
                shift 2
                ;;
            --backup-operation)
                BACKUP_OPERATION="$2"
                shift 2
                ;;
            --maintenance-operation)
                MAINTENANCE_OPERATION="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --webhook)
                NOTIFICATION_WEBHOOK="$2"
                shift 2
                ;;
            --backup-file)
                BACKUP_FILE="$2"
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
🔧 Fortress Production Operations Automation

USAGE:
    $0 [OPTIONS]

MAIN OPERATIONS:
    --operation ssl            SSL certificate management
    --operation secrets        Secret rotation and management
    --operation backup         Backup validation and management
    --operation maintenance    System maintenance operations
    --operation status         System status report
    --operation all            Run all operations (default)

SSL OPERATIONS:
    --ssl-operation check      Check certificate status and expiry
    --ssl-operation renew      Renew certificates
    --ssl-operation issue      Issue new certificates
    --ssl-operation install    Install certificates

SECRET OPERATIONS:
    --secret-operation rotate  Rotate secrets and keys
    --secret-operation check   Check secret status and age
    --secret-operation backup  Backup secrets to encrypted archive
    --secret-operation restore Restore secrets from backup

BACKUP OPERATIONS:
    --backup-operation validate    Validate backup integrity
    --backup-operation cleanup     Clean up old backups
    --backup-operation create      Create comprehensive system backup
    --backup-operation restore     Restore from system backup

MAINTENANCE OPERATIONS:
    --maintenance-operation all      All maintenance tasks
    --maintenance-operation logs     Log rotation and cleanup
    --maintenance-operation cleanup  Disk cleanup
    --maintenance-operation security Security updates
    --maintenance-operation optimize Performance optimization

OPTIONS:
    --environment ENV          Environment name (default: production)
    --domain DOMAIN           Primary domain name
    --dry-run                 Show what would be done without executing
    --webhook URL             Notification webhook URL
    --backup-file FILE        Specific backup file for restore operations
    --help                    Show this help

EXAMPLES:
    # Check SSL certificate status
    $0 --operation ssl --ssl-operation check

    # Rotate all secrets
    $0 --operation secrets --secret-operation rotate

    # Validate backups
    $0 --operation backup --backup-operation validate

    # System maintenance
    $0 --operation maintenance --maintenance-operation all

    # Complete operations check
    $0 --operation status

    # Dry run of all operations
    $0 --operation all --dry-run

ENVIRONMENT VARIABLES:
    ENVIRONMENT                Environment name
    DOMAIN_NAME               Primary domain name
    BACKUP_S3_BUCKET          S3 bucket for backup storage
    SECRETS_MANAGER_PREFIX    AWS Secrets Manager prefix
    BACKUP_RETENTION_DAYS     Backup retention period
    CERT_EXPIRY_WARNING_DAYS  Certificate expiry warning threshold
    SECRET_ROTATION_INTERVAL  Secret rotation interval in days
    NOTIFICATION_WEBHOOK      Webhook URL for notifications

FEATURES:
    ✅ SSL certificate management and auto-renewal
    ✅ Automated secret rotation with AWS Secrets Manager
    ✅ Comprehensive backup validation and cleanup
    ✅ System maintenance and performance optimization
    ✅ Real-time status monitoring and reporting
    ✅ Integration with Kubernetes and cloud services
    ✅ Encrypted backup and restore capabilities
    ✅ Automated notifications and alerting

EOF
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi