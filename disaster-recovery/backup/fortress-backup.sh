#!/bin/bash

# =============================================================================
# Pat Fortress Comprehensive Backup System
# =============================================================================
# This script orchestrates all backup operations for the Pat Fortress platform
# including databases, configurations, secrets, logs, and application data
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONFIGURATION AND ENVIRONMENT
# =============================================================================

# Script metadata
readonly SCRIPT_NAME="fortress-backup"
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Load configuration
readonly CONFIG_FILE="${BASE_DIR}/policies/backup-config.yaml"
readonly SECRETS_FILE="${BASE_DIR}/policies/backup-secrets.env"

# Backup directories
readonly BACKUP_BASE_DIR="${BACKUP_BASE_DIR:-/var/lib/fortress/backups}"
readonly LOCAL_BACKUP_DIR="${BACKUP_BASE_DIR}/local"
readonly REMOTE_BACKUP_DIR="${BACKUP_BASE_DIR}/remote"
readonly CLOUD_BACKUP_DIR="${BACKUP_BASE_DIR}/cloud"

# Timestamps
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly DATE_STAMP=$(date +%Y%m%d)
readonly RETENTION_DATE=$(date -d "30 days ago" +%Y%m%d)

# Logging
readonly LOG_DIR="/var/log/fortress/backup"
readonly LOG_FILE="${LOG_DIR}/backup_${TIMESTAMP}.log"
readonly METRICS_FILE="${LOG_DIR}/backup_metrics_${DATE_STAMP}.json"

# Lock file for preventing concurrent runs
readonly LOCK_FILE="/var/run/fortress-backup.lock"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

die() {
    log_error "$@"
    exit 1
}

# Validate requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check required commands
    local required_commands=(
        "docker" "docker-compose" "pg_dump" "redis-cli"
        "aws" "gcloud" "vault" "gpg" "rsync" "tar"
        "jq" "yq" "curl" "nc"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            die "Required command '$cmd' not found"
        fi
    done
    
    # Check directories
    mkdir -p "$LOG_DIR" "$LOCAL_BACKUP_DIR" "$REMOTE_BACKUP_DIR" "$CLOUD_BACKUP_DIR"
    
    # Check lock file
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
        if ps -p "$lock_pid" > /dev/null 2>&1; then
            die "Backup already running (PID: $lock_pid)"
        else
            log_warn "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    
    echo $$ > "$LOCK_FILE"
    trap cleanup_lock EXIT
    
    log_info "Requirements check completed"
}

cleanup_lock() {
    rm -f "$LOCK_FILE"
}

# Load secrets securely
load_secrets() {
    if [[ -f "$SECRETS_FILE" ]]; then
        set -a
        source "$SECRETS_FILE"
        set +a
        log_info "Backup secrets loaded"
    else
        log_warn "Secrets file not found, using environment variables"
    fi
}

# Metrics collection
collect_metrics() {
    local operation="$1"
    local status="$2"
    local size="${3:-0}"
    local duration="${4:-0}"
    
    local metric_entry=$(jq -n \
        --arg timestamp "$(date -Iseconds)" \
        --arg operation "$operation" \
        --arg status "$status" \
        --arg size "$size" \
        --arg duration "$duration" \
        '{
            timestamp: $timestamp,
            operation: $operation,
            status: $status,
            size_bytes: ($size | tonumber),
            duration_seconds: ($duration | tonumber)
        }')
    
    echo "$metric_entry" >> "$METRICS_FILE"
}

# =============================================================================
# BACKUP FUNCTIONS
# =============================================================================

# PostgreSQL Database Backup
backup_postgresql() {
    log_info "Starting PostgreSQL backup..."
    local start_time=$(date +%s)
    
    local pg_container="fortress-postgres-primary"
    local backup_file="${LOCAL_BACKUP_DIR}/postgres_${TIMESTAMP}.sql"
    local backup_file_compressed="${backup_file}.zst"
    
    # Check if container is running
    if ! docker ps --format "table {{.Names}}" | grep -q "^${pg_container}$"; then
        log_error "PostgreSQL container not running"
        collect_metrics "postgresql_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
    
    # Create database backup with pg_dump
    log_info "Creating PostgreSQL dump..."
    if docker exec "$pg_container" pg_dump \
        -U "${POSTGRES_USER:-fortress_user}" \
        -d "${POSTGRES_DB:-fortress_production}" \
        --no-password \
        --verbose \
        --format=custom \
        --compress=0 \
        --no-privileges \
        --no-owner > "$backup_file"; then
        
        log_info "PostgreSQL dump completed: $(du -sh "$backup_file" | cut -f1)"
        
        # Compress with zstd
        if zstd -T0 -19 "$backup_file" -o "$backup_file_compressed"; then
            rm "$backup_file"
            local backup_size=$(stat -c%s "$backup_file_compressed")
            log_info "PostgreSQL backup compressed: $(du -sh "$backup_file_compressed" | cut -f1)"
            
            # Encrypt backup
            if encrypt_file "$backup_file_compressed"; then
                collect_metrics "postgresql_backup" "success" "$backup_size" "$(($(date +%s) - start_time))"
                log_info "PostgreSQL backup completed successfully"
            else
                collect_metrics "postgresql_backup" "failed" "0" "$(($(date +%s) - start_time))"
                return 1
            fi
        else
            log_error "Failed to compress PostgreSQL backup"
            collect_metrics "postgresql_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "PostgreSQL dump failed"
        collect_metrics "postgresql_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# PostgreSQL WAL Archive Backup
backup_postgresql_wal() {
    log_info "Starting PostgreSQL WAL archive backup..."
    local start_time=$(date +%s)
    
    local pg_container="fortress-postgres-primary"
    local wal_backup_dir="${LOCAL_BACKUP_DIR}/wal/${DATE_STAMP}"
    
    mkdir -p "$wal_backup_dir"
    
    # Archive WAL files
    log_info "Archiving PostgreSQL WAL files..."
    if docker exec "$pg_container" find /var/lib/postgresql/data/pg_wal \
        -name "*.backup" -o -name "[0-9A-F]*" -type f -mtime -1 \
        -exec cp {} /tmp/wal_export/ \;; then
        
        # Copy WAL files from container
        docker cp "${pg_container}:/tmp/wal_export/." "$wal_backup_dir/"
        
        # Compress WAL archive
        local wal_archive="${LOCAL_BACKUP_DIR}/wal_${DATE_STAMP}.tar.zst"
        if tar -C "$wal_backup_dir" -cf - . | zstd -T0 -19 > "$wal_archive"; then
            local archive_size=$(stat -c%s "$wal_archive")
            log_info "WAL archive created: $(du -sh "$wal_archive" | cut -f1)"
            
            # Encrypt WAL archive
            if encrypt_file "$wal_archive"; then
                rm -rf "$wal_backup_dir"
                collect_metrics "postgresql_wal_backup" "success" "$archive_size" "$(($(date +%s) - start_time))"
                log_info "PostgreSQL WAL backup completed successfully"
            else
                collect_metrics "postgresql_wal_backup" "failed" "0" "$(($(date +%s) - start_time))"
                return 1
            fi
        else
            log_error "Failed to create WAL archive"
            collect_metrics "postgresql_wal_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "Failed to archive WAL files"
        collect_metrics "postgresql_wal_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# Redis Backup
backup_redis() {
    log_info "Starting Redis backup..."
    local start_time=$(date +%s)
    
    local redis_container="fortress-redis-master"
    local backup_file="${LOCAL_BACKUP_DIR}/redis_${TIMESTAMP}.rdb"
    local backup_file_compressed="${backup_file}.zst"
    
    # Check if container is running
    if ! docker ps --format "table {{.Names}}" | grep -q "^${redis_container}$"; then
        log_error "Redis container not running"
        collect_metrics "redis_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
    
    # Trigger Redis save and copy RDB file
    log_info "Creating Redis snapshot..."
    if docker exec "$redis_container" redis-cli --no-auth-warning -a "${REDIS_PASSWORD}" BGSAVE; then
        # Wait for background save to complete
        while docker exec "$redis_container" redis-cli --no-auth-warning -a "${REDIS_PASSWORD}" LASTSAVE | \
              grep -q "$(docker exec "$redis_container" redis-cli --no-auth-warning -a "${REDIS_PASSWORD}" LASTSAVE)"; do
            sleep 1
        done
        
        # Copy RDB file
        if docker cp "${redis_container}:/data/dump.rdb" "$backup_file"; then
            log_info "Redis dump completed: $(du -sh "$backup_file" | cut -f1)"
            
            # Compress with zstd
            if zstd -T0 -19 "$backup_file" -o "$backup_file_compressed"; then
                rm "$backup_file"
                local backup_size=$(stat -c%s "$backup_file_compressed")
                log_info "Redis backup compressed: $(du -sh "$backup_file_compressed" | cut -f1)"
                
                # Encrypt backup
                if encrypt_file "$backup_file_compressed"; then
                    collect_metrics "redis_backup" "success" "$backup_size" "$(($(date +%s) - start_time))"
                    log_info "Redis backup completed successfully"
                else
                    collect_metrics "redis_backup" "failed" "0" "$(($(date +%s) - start_time))"
                    return 1
                fi
            else
                log_error "Failed to compress Redis backup"
                collect_metrics "redis_backup" "failed" "0" "$(($(date +%s) - start_time))"
                return 1
            fi
        else
            log_error "Failed to copy Redis dump file"
            collect_metrics "redis_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "Failed to create Redis snapshot"
        collect_metrics "redis_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# Configuration and Secrets Backup
backup_configurations() {
    log_info "Starting configuration backup..."
    local start_time=$(date +%s)
    
    local config_backup_dir="${LOCAL_BACKUP_DIR}/config_${TIMESTAMP}"
    mkdir -p "$config_backup_dir"
    
    # Backup Docker Compose configurations
    if [[ -f "${BASE_DIR}/../docker-compose.fortress.yml" ]]; then
        cp "${BASE_DIR}/../docker-compose.fortress.yml" "${config_backup_dir}/"
    fi
    
    # Backup Kubernetes manifests
    if [[ -d "${BASE_DIR}/../k8s" ]]; then
        cp -r "${BASE_DIR}/../k8s" "${config_backup_dir}/"
    fi
    
    # Backup monitoring configurations
    if [[ -d "${BASE_DIR}/../monitoring" ]]; then
        cp -r "${BASE_DIR}/../monitoring" "${config_backup_dir}/"
    fi
    
    # Backup Terraform configurations
    if [[ -d "${BASE_DIR}/../terraform" ]]; then
        cp -r "${BASE_DIR}/../terraform" "${config_backup_dir}/"
    fi
    
    # Backup application configurations
    local app_configs=(
        "config"
        "nginx"
        "scripts"
    )
    
    for config_dir in "${app_configs[@]}"; do
        if [[ -d "${BASE_DIR}/../${config_dir}" ]]; then
            cp -r "${BASE_DIR}/../${config_dir}" "${config_backup_dir}/"
        fi
    done
    
    # Create compressed archive
    local config_archive="${LOCAL_BACKUP_DIR}/config_${TIMESTAMP}.tar.zst"
    if tar -C "$config_backup_dir" -cf - . | zstd -T0 -19 > "$config_archive"; then
        local archive_size=$(stat -c%s "$config_archive")
        log_info "Configuration archive created: $(du -sh "$config_archive" | cut -f1)"
        
        # Encrypt configuration archive
        if encrypt_file "$config_archive"; then
            rm -rf "$config_backup_dir"
            collect_metrics "config_backup" "success" "$archive_size" "$(($(date +%s) - start_time))"
            log_info "Configuration backup completed successfully"
        else
            collect_metrics "config_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "Failed to create configuration archive"
        collect_metrics "config_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# Application Data Backup
backup_application_data() {
    log_info "Starting application data backup..."
    local start_time=$(date +%s)
    
    local data_backup_dir="${LOCAL_BACKUP_DIR}/appdata_${TIMESTAMP}"
    mkdir -p "$data_backup_dir"
    
    # Backup persistent volumes
    local volume_dirs=(
        "/var/lib/fortress/app/storage"
        "/var/lib/fortress/app/emails"
        "/var/lib/fortress/app/plugins"
        "/var/lib/fortress/app/workflows"
        "/var/lib/fortress/app/workflow-state"
    )
    
    for vol_dir in "${volume_dirs[@]}"; do
        if [[ -d "$vol_dir" ]]; then
            local vol_name=$(basename "$vol_dir")
            rsync -av --progress "$vol_dir/" "${data_backup_dir}/${vol_name}/"
        fi
    done
    
    # Create compressed archive
    local data_archive="${LOCAL_BACKUP_DIR}/appdata_${TIMESTAMP}.tar.zst"
    if tar -C "$data_backup_dir" -cf - . | zstd -T0 -19 > "$data_archive"; then
        local archive_size=$(stat -c%s "$data_archive")
        log_info "Application data archive created: $(du -sh "$data_archive" | cut -f1)"
        
        # Encrypt data archive
        if encrypt_file "$data_archive"; then
            rm -rf "$data_backup_dir"
            collect_metrics "appdata_backup" "success" "$archive_size" "$(($(date +%s) - start_time))"
            log_info "Application data backup completed successfully"
        else
            collect_metrics "appdata_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "Failed to create application data archive"
        collect_metrics "appdata_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# Log Backup
backup_logs() {
    log_info "Starting log backup..."
    local start_time=$(date +%s)
    
    local log_backup_dir="${LOCAL_BACKUP_DIR}/logs_${TIMESTAMP}"
    mkdir -p "$log_backup_dir"
    
    # Backup application logs
    local log_dirs=(
        "/var/log/fortress"
        "/var/lib/fortress/logs"
    )
    
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            rsync -av --progress "$log_dir/" "${log_backup_dir}/$(basename "$log_dir")/"
        fi
    done
    
    # Backup Docker container logs (last 7 days)
    docker logs fortress-postgres-primary --since "168h" > "${log_backup_dir}/postgres-primary.log" 2>&1 || true
    docker logs fortress-redis-master --since "168h" > "${log_backup_dir}/redis-master.log" 2>&1 || true
    docker logs fortress-core --since "168h" > "${log_backup_dir}/fortress-core.log" 2>&1 || true
    docker logs fortress-api --since "168h" > "${log_backup_dir}/fortress-api.log" 2>&1 || true
    
    # Create compressed archive
    local log_archive="${LOCAL_BACKUP_DIR}/logs_${TIMESTAMP}.tar.zst"
    if tar -C "$log_backup_dir" -cf - . | zstd -T0 -19 > "$log_archive"; then
        local archive_size=$(stat -c%s "$log_archive")
        log_info "Log archive created: $(du -sh "$log_archive" | cut -f1)"
        
        # Encrypt log archive
        if encrypt_file "$log_archive"; then
            rm -rf "$log_backup_dir"
            collect_metrics "logs_backup" "success" "$archive_size" "$(($(date +%s) - start_time))"
            log_info "Log backup completed successfully"
        else
            collect_metrics "logs_backup" "failed" "0" "$(($(date +%s) - start_time))"
            return 1
        fi
    else
        log_error "Failed to create log archive"
        collect_metrics "logs_backup" "failed" "0" "$(($(date +%s) - start_time))"
        return 1
    fi
}

# Encryption function
encrypt_file() {
    local file_path="$1"
    local encrypted_file="${file_path}.gpg"
    
    if [[ -n "${BACKUP_ENCRYPTION_KEY:-}" ]]; then
        if gpg --batch --yes --trust-model always \
               --cipher-algo AES256 \
               --compress-algo 2 \
               --recipient "$BACKUP_ENCRYPTION_KEY" \
               --encrypt "$file_path"; then
            rm "$file_path"
            mv "${file_path}.gpg" "$encrypted_file"
            log_info "File encrypted: $(basename "$encrypted_file")"
            return 0
        else
            log_error "Failed to encrypt file: $(basename "$file_path")"
            return 1
        fi
    else
        log_warn "No encryption key configured, skipping encryption"
        return 0
    fi
}

# Backup verification
verify_backup() {
    local backup_file="$1"
    local backup_type="$2"
    
    log_info "Verifying backup: $(basename "$backup_file")"
    
    # Check file exists and is readable
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Check file is not empty
    if [[ ! -s "$backup_file" ]]; then
        log_error "Backup file is empty: $backup_file"
        return 1
    fi
    
    # Type-specific verification
    case "$backup_type" in
        "postgresql")
            # Verify PostgreSQL dump integrity
            if file "$backup_file" | grep -q "PostgreSQL"; then
                log_info "PostgreSQL backup verified"
                return 0
            else
                log_error "PostgreSQL backup verification failed"
                return 1
            fi
            ;;
        "redis")
            # Verify Redis RDB file
            if file "$backup_file" | grep -q "Redis"; then
                log_info "Redis backup verified"
                return 0
            else
                log_error "Redis backup verification failed"
                return 1
            fi
            ;;
        "archive")
            # Verify archive integrity
            if zstd -t "$backup_file" >/dev/null 2>&1; then
                log_info "Archive backup verified"
                return 0
            else
                log_error "Archive backup verification failed"
                return 1
            fi
            ;;
        *)
            log_info "Generic backup verification completed"
            return 0
            ;;
    esac
}

# Remote backup sync
sync_to_remote() {
    log_info "Starting remote backup sync..."
    local start_time=$(date +%s)
    
    if [[ -n "${REMOTE_BACKUP_HOST:-}" ]]; then
        # Sync to remote server via rsync
        if rsync -avz --progress --delete \
                 -e "ssh -o StrictHostKeyChecking=no" \
                 "$LOCAL_BACKUP_DIR/" \
                 "${REMOTE_BACKUP_USER:-backup}@${REMOTE_BACKUP_HOST}:${REMOTE_BACKUP_PATH:-/backups/fortress}/"; then
            
            collect_metrics "remote_sync" "success" "0" "$(($(date +%s) - start_time))"
            log_info "Remote backup sync completed successfully"
        else
            collect_metrics "remote_sync" "failed" "0" "$(($(date +%s) - start_time))"
            log_error "Remote backup sync failed"
            return 1
        fi
    else
        log_info "No remote backup host configured, skipping remote sync"
    fi
}

# Cloud backup sync
sync_to_cloud() {
    log_info "Starting cloud backup sync..."
    local start_time=$(date +%s)
    
    # AWS S3 sync
    if [[ -n "${AWS_S3_BACKUP_BUCKET:-}" ]]; then
        if aws s3 sync "$LOCAL_BACKUP_DIR/" "s3://${AWS_S3_BACKUP_BUCKET}/fortress/${DATE_STAMP}/" \
                 --storage-class STANDARD_IA \
                 --server-side-encryption AES256; then
            log_info "AWS S3 backup sync completed successfully"
        else
            log_error "AWS S3 backup sync failed"
            return 1
        fi
    fi
    
    # Google Cloud Storage sync
    if [[ -n "${GCS_BACKUP_BUCKET:-}" ]]; then
        if gsutil -m rsync -r -d "$LOCAL_BACKUP_DIR/" "gs://${GCS_BACKUP_BUCKET}/fortress/${DATE_STAMP}/"; then
            log_info "Google Cloud Storage backup sync completed successfully"
        else
            log_error "Google Cloud Storage backup sync failed"
            return 1
        fi
    fi
    
    collect_metrics "cloud_sync" "success" "0" "$(($(date +%s) - start_time))"
    log_info "Cloud backup sync completed"
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups..."
    
    # Local cleanup (keep 24 hours)
    find "$LOCAL_BACKUP_DIR" -type f -mtime +1 -delete
    log_info "Old local backups cleaned up"
    
    # Remote cleanup (keep 30 days)
    if [[ -n "${REMOTE_BACKUP_HOST:-}" ]]; then
        ssh "${REMOTE_BACKUP_USER:-backup}@${REMOTE_BACKUP_HOST}" \
            "find ${REMOTE_BACKUP_PATH:-/backups/fortress}/ -type f -mtime +30 -delete" || true
        log_info "Old remote backups cleaned up"
    fi
    
    # Cloud cleanup (keep 365 days)
    if [[ -n "${AWS_S3_BACKUP_BUCKET:-}" ]]; then
        local old_date=$(date -d "365 days ago" +%Y%m%d)
        aws s3 rm "s3://${AWS_S3_BACKUP_BUCKET}/fortress/" --recursive \
            --exclude "*" --include "*${old_date}*" || true
        log_info "Old AWS S3 backups cleaned up"
    fi
    
    if [[ -n "${GCS_BACKUP_BUCKET:-}" ]]; then
        local old_date=$(date -d "365 days ago" +%Y%m%d)
        gsutil -m rm -r "gs://${GCS_BACKUP_BUCKET}/fortress/*${old_date}*" || true
        log_info "Old GCS backups cleaned up"
    fi
}

# Health checks
perform_health_checks() {
    log_info "Performing system health checks..."
    
    # Check services
    local services=(
        "fortress-postgres-primary:5432"
        "fortress-redis-master:6379"
        "fortress-core:8025"
        "fortress-api:8025"
    )
    
    for service in "${services[@]}"; do
        local host="${service%:*}"
        local port="${service#*:}"
        
        if docker exec "$host" nc -z localhost "$port" 2>/dev/null; then
            log_info "Service healthy: $host:$port"
        else
            log_warn "Service unhealthy: $host:$port"
        fi
    done
    
    # Check disk space
    local disk_usage=$(df /var/lib/fortress | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ "$disk_usage" -gt 85 ]]; then
        log_warn "Disk usage high: ${disk_usage}%"
    else
        log_info "Disk usage normal: ${disk_usage}%"
    fi
    
    log_info "Health checks completed"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local start_time=$(date +%s)
    
    log_info "=================================================="
    log_info "Pat Fortress Backup System v${SCRIPT_VERSION}"
    log_info "Starting backup process at $(date)"
    log_info "=================================================="
    
    # Initialize
    check_requirements
    load_secrets
    perform_health_checks
    
    # Execute backup operations
    local backup_success=true
    
    # Core data backups
    backup_postgresql || backup_success=false
    backup_postgresql_wal || backup_success=false
    backup_redis || backup_success=false
    
    # Configuration and application data
    backup_configurations || backup_success=false
    backup_application_data || backup_success=false
    backup_logs || backup_success=false
    
    # Sync to remote locations
    sync_to_remote || backup_success=false
    sync_to_cloud || backup_success=false
    
    # Cleanup
    cleanup_old_backups
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    if [[ "$backup_success" == true ]]; then
        log_info "=================================================="
        log_info "Backup process completed successfully"
        log_info "Total duration: ${total_duration} seconds"
        log_info "=================================================="
        collect_metrics "full_backup" "success" "0" "$total_duration"
        exit 0
    else
        log_error "=================================================="
        log_error "Backup process completed with errors"
        log_error "Total duration: ${total_duration} seconds"
        log_error "=================================================="
        collect_metrics "full_backup" "failed" "0" "$total_duration"
        exit 1
    fi
}

# Handle signals
trap 'log_error "Backup interrupted"; cleanup_lock; exit 1' INT TERM

# Execute main function
main "$@"