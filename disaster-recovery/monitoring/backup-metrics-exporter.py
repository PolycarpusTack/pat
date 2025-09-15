#!/usr/bin/env python3

"""
Pat Fortress Backup Metrics Exporter
====================================
Prometheus metrics exporter for backup and disaster recovery operations.
Collects metrics from backup logs, state files, and system monitoring.
"""

import os
import sys
import time
import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse

import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
import yaml
import psutil

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Configuration management for the backup metrics exporter."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "/etc/fortress/backup/metrics-config.yaml"
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        default_config = {
            'metrics': {
                'listen_address': '0.0.0.0',
                'listen_port': 9100,
                'collection_interval': 30,
                'log_retention_days': 30
            },
            'paths': {
                'backup_logs': '/var/log/fortress/backup',
                'backup_metrics': '/var/log/fortress/backup/backup_metrics_*.json',
                'recovery_logs': '/var/log/fortress/recovery',
                'recovery_metrics': '/var/log/fortress/recovery/recovery_metrics_*.json',
                'failover_logs': '/var/log/fortress/failover',
                'backup_state': '/var/lib/fortress/backups',
                'dr_state': '/var/lib/fortress/recovery'
            },
            'database': {
                'host': 'fortress-postgres-primary',
                'port': 5432,
                'database': 'fortress_production',
                'user': 'fortress_user'
            },
            'redis': {
                'host': 'fortress-redis-master',
                'port': 6379
            },
            'storage': {
                'local_path': '/var/lib/fortress/backups/local',
                'remote_enabled': True,
                'cloud_enabled': True
            }
        }
        
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    config_from_file = yaml.safe_load(f)
                    default_config.update(config_from_file)
            except Exception as e:
                logging.warning(f"Failed to load config file {self.config_file}: {e}")
                
        return default_config

# =============================================================================
# METRICS DEFINITIONS
# =============================================================================

class FortressMetrics:
    """Prometheus metrics for Fortress backup and disaster recovery."""
    
    def __init__(self):
        # Backup operation metrics
        self.backup_attempts_total = Counter(
            'fortress_backup_attempts_total',
            'Total number of backup attempts',
            ['backup_type', 'storage_tier', 'instance']
        )
        
        self.backup_success_total = Counter(
            'fortress_backup_success_total', 
            'Total number of successful backups',
            ['backup_type', 'storage_tier', 'instance']
        )
        
        self.backup_duration_seconds = Histogram(
            'fortress_backup_duration_seconds',
            'Time taken for backup operations',
            ['backup_type', 'storage_tier', 'instance'],
            buckets=[30, 60, 300, 600, 1800, 3600, 7200]
        )
        
        self.backup_size_bytes = Gauge(
            'fortress_backup_size_bytes',
            'Size of backup files in bytes',
            ['backup_type', 'storage_tier', 'instance']
        )
        
        # Storage metrics
        self.backup_storage_total_bytes = Gauge(
            'fortress_backup_storage_total_bytes',
            'Total backup storage capacity in bytes',
            ['storage_tier', 'location']
        )
        
        self.backup_storage_used_bytes = Gauge(
            'fortress_backup_storage_used_bytes',
            'Used backup storage in bytes',
            ['storage_tier', 'location']
        )
        
        self.backup_storage_free_bytes = Gauge(
            'fortress_backup_storage_free_bytes',
            'Free backup storage in bytes',
            ['storage_tier', 'location']
        )
        
        # Integrity and validation metrics
        self.backup_integrity_check_success = Gauge(
            'fortress_backup_integrity_check_success',
            'Success status of backup integrity checks',
            ['backup_type', 'instance']
        )
        
        self.backup_restore_test_success = Gauge(
            'fortress_backup_restore_test_success',
            'Success status of backup restore tests',
            ['backup_type', 'instance']
        )
        
        # Replication metrics
        self.postgres_replication_lag_seconds = Gauge(
            'fortress_postgres_replication_lag_seconds',
            'PostgreSQL replication lag in seconds',
            ['instance', 'replica_name']
        )
        
        self.redis_replication_lag_seconds = Gauge(
            'fortress_redis_replication_lag_seconds',
            'Redis replication lag in seconds',
            ['instance', 'replica_name']
        )
        
        # Recovery metrics
        self.recovery_attempts_total = Counter(
            'fortress_recovery_attempts_total',
            'Total number of recovery attempts',
            ['recovery_type', 'instance']
        )
        
        self.recovery_success_total = Counter(
            'fortress_recovery_success_total',
            'Total number of successful recoveries', 
            ['recovery_type', 'instance']
        )
        
        self.recovery_time_seconds = Histogram(
            'fortress_recovery_time_seconds',
            'Time taken for recovery operations',
            ['recovery_type', 'service_type', 'instance'],
            buckets=[30, 60, 300, 600, 900, 1800, 3600]
        )
        
        self.recovery_point_lag_seconds = Gauge(
            'fortress_recovery_point_lag_seconds',
            'Recovery point lag in seconds (RPO)',
            ['recovery_type', 'instance']
        )
        
        # Disaster recovery test metrics
        self.dr_test_attempts_total = Counter(
            'fortress_dr_test_attempts_total',
            'Total number of DR test attempts',
            ['test_type', 'instance']
        )
        
        self.dr_test_success = Gauge(
            'fortress_dr_test_success',
            'Success status of DR tests',
            ['test_type', 'instance']
        )
        
        # Failover metrics
        self.failover_attempts_total = Counter(
            'fortress_failover_attempts_total',
            'Total number of failover attempts',
            ['source_region', 'target_region', 'instance']
        )
        
        self.failover_success_total = Counter(
            'fortress_failover_success_total',
            'Total number of successful failovers',
            ['source_region', 'target_region', 'instance']
        )
        
        self.failover_duration_seconds = Histogram(
            'fortress_failover_duration_seconds',
            'Time taken for failover operations',
            ['source_region', 'target_region', 'instance'],
            buckets=[60, 300, 600, 900, 1800, 3600]
        )
        
        # Service health metrics
        self.service_health_status = Gauge(
            'fortress_service_health_status',
            'Health status of Fortress services (1=healthy, 0=unhealthy)',
            ['service_name', 'instance']
        )
        
        # System resource metrics
        self.system_disk_usage_percent = Gauge(
            'fortress_system_disk_usage_percent',
            'Disk usage percentage for backup storage',
            ['mount_point', 'instance']
        )
        
        self.system_memory_usage_bytes = Gauge(
            'fortress_system_memory_usage_bytes',
            'Memory usage during backup operations',
            ['process', 'instance']
        )

# =============================================================================
# METRICS COLLECTOR
# =============================================================================

class FortressMetricsCollector:
    """Main metrics collector for Fortress backup and disaster recovery."""
    
    def __init__(self, config: Config):
        self.config = config
        self.metrics = FortressMetrics()
        self.logger = self._setup_logging()
        self.running = False
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('fortress-metrics')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def start(self):
        """Start the metrics collector."""
        self.logger.info("Starting Fortress Metrics Exporter")
        
        # Start Prometheus HTTP server
        listen_addr = self.config.config['metrics']['listen_address']
        listen_port = self.config.config['metrics']['listen_port']
        
        start_http_server(listen_port, addr=listen_addr)
        self.logger.info(f"Metrics server started on {listen_addr}:{listen_port}")
        
        # Start metrics collection
        self.running = True
        collection_interval = self.config.config['metrics']['collection_interval']
        
        while self.running:
            try:
                self._collect_all_metrics()
                time.sleep(collection_interval)
            except KeyboardInterrupt:
                self.logger.info("Received shutdown signal")
                break
            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
                time.sleep(5)  # Brief pause before retry
                
        self.logger.info("Fortress Metrics Exporter stopped")
    
    def stop(self):
        """Stop the metrics collector."""
        self.running = False
    
    def _collect_all_metrics(self):
        """Collect all metrics from various sources."""
        try:
            self._collect_backup_metrics()
            self._collect_storage_metrics() 
            self._collect_replication_metrics()
            self._collect_recovery_metrics()
            self._collect_dr_test_metrics()
            self._collect_failover_metrics()
            self._collect_service_health_metrics()
            self._collect_system_metrics()
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
    
    def _collect_backup_metrics(self):
        """Collect backup operation metrics from log files."""
        backup_metrics_pattern = self.config.config['paths']['backup_metrics']
        metrics_files = list(Path().glob(backup_metrics_pattern))
        
        for metrics_file in metrics_files[-10:]:  # Process last 10 files
            try:
                with open(metrics_file, 'r') as f:
                    for line in f:
                        try:
                            metric_data = json.loads(line.strip())
                            self._process_backup_metric(metric_data)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                self.logger.warning(f"Failed to read {metrics_file}: {e}")
    
    def _process_backup_metric(self, data: Dict[str, Any]):
        """Process individual backup metric entry."""
        operation = data.get('operation', '')
        status = data.get('status', '')
        duration = float(data.get('duration_seconds', 0))
        size_bytes = float(data.get('size_bytes', 0))
        
        # Determine backup type and storage tier from operation
        backup_type = 'unknown'
        storage_tier = 'local'
        
        if 'postgresql' in operation:
            backup_type = 'postgresql'
        elif 'redis' in operation:
            backup_type = 'redis'
        elif 'config' in operation:
            backup_type = 'configuration'
        elif 'appdata' in operation:
            backup_type = 'application_data'
        elif 'logs' in operation:
            backup_type = 'logs'
        
        if 'remote' in operation:
            storage_tier = 'remote'
        elif 'cloud' in operation:
            storage_tier = 'cloud'
        
        instance = 'primary'  # Could be extracted from data if available
        
        # Update metrics
        self.metrics.backup_attempts_total.labels(
            backup_type=backup_type,
            storage_tier=storage_tier,
            instance=instance
        ).inc()
        
        if status == 'success':
            self.metrics.backup_success_total.labels(
                backup_type=backup_type,
                storage_tier=storage_tier,
                instance=instance
            ).inc()
        
        if duration > 0:
            self.metrics.backup_duration_seconds.labels(
                backup_type=backup_type,
                storage_tier=storage_tier,
                instance=instance
            ).observe(duration)
        
        if size_bytes > 0:
            self.metrics.backup_size_bytes.labels(
                backup_type=backup_type,
                storage_tier=storage_tier,
                instance=instance
            ).set(size_bytes)
    
    def _collect_storage_metrics(self):
        """Collect storage utilization metrics."""
        storage_config = self.config.config['storage']
        
        # Local storage metrics
        if Path(storage_config['local_path']).exists():
            disk_usage = psutil.disk_usage(storage_config['local_path'])
            
            self.metrics.backup_storage_total_bytes.labels(
                storage_tier='local',
                location='primary'
            ).set(disk_usage.total)
            
            self.metrics.backup_storage_used_bytes.labels(
                storage_tier='local',
                location='primary'
            ).set(disk_usage.used)
            
            self.metrics.backup_storage_free_bytes.labels(
                storage_tier='local',
                location='primary'
            ).set(disk_usage.free)
    
    def _collect_replication_metrics(self):
        """Collect database and cache replication lag metrics."""
        try:
            # PostgreSQL replication lag (this would need actual DB connection)
            # For demonstration, using mock data
            self.metrics.postgres_replication_lag_seconds.labels(
                instance='primary',
                replica_name='replica-1'
            ).set(5)  # Mock 5 second lag
            
            # Redis replication lag (this would need actual Redis connection)
            self.metrics.redis_replication_lag_seconds.labels(
                instance='primary', 
                replica_name='sentinel-1'
            ).set(1)  # Mock 1 second lag
            
        except Exception as e:
            self.logger.warning(f"Failed to collect replication metrics: {e}")
    
    def _collect_recovery_metrics(self):
        """Collect disaster recovery metrics from log files."""
        recovery_metrics_pattern = self.config.config['paths']['recovery_metrics']
        metrics_files = list(Path().glob(recovery_metrics_pattern))
        
        for metrics_file in metrics_files[-5:]:  # Process last 5 files
            try:
                with open(metrics_file, 'r') as f:
                    for line in f:
                        try:
                            metric_data = json.loads(line.strip())
                            self._process_recovery_metric(metric_data)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                self.logger.warning(f"Failed to read {metrics_file}: {e}")
    
    def _process_recovery_metric(self, data: Dict[str, Any]):
        """Process individual recovery metric entry."""
        operation = data.get('operation', '')
        status = data.get('status', '')
        duration = float(data.get('duration_seconds', 0))
        
        recovery_type = 'unknown'
        service_type = 'unknown'
        
        if 'service_recovery' in operation:
            recovery_type = 'service_failure'
            service_type = 'application'
        elif 'database_recovery' in operation:
            recovery_type = 'database_corruption'
            service_type = 'database'
        elif 'infrastructure_recovery' in operation:
            recovery_type = 'infrastructure_failure'
            service_type = 'infrastructure'
        elif 'pitr_recovery' in operation:
            recovery_type = 'point_in_time'
            service_type = 'database'
        
        instance = 'primary'
        
        # Update metrics
        self.metrics.recovery_attempts_total.labels(
            recovery_type=recovery_type,
            instance=instance
        ).inc()
        
        if status == 'success':
            self.metrics.recovery_success_total.labels(
                recovery_type=recovery_type,
                instance=instance
            ).inc()
        
        if duration > 0:
            self.metrics.recovery_time_seconds.labels(
                recovery_type=recovery_type,
                service_type=service_type,
                instance=instance
            ).observe(duration)
    
    def _collect_dr_test_metrics(self):
        """Collect disaster recovery test metrics."""
        # This would read from DR test result files
        # For demonstration, setting mock values
        
        test_types = ['backup_integrity', 'service_restart', 'database_recovery', 'rto_validation']
        
        for test_type in test_types:
            # Mock test success (in production, read from actual test results)
            success_value = 1 if test_type != 'database_recovery' else 0  # Mock one failure
            
            self.metrics.dr_test_success.labels(
                test_type=test_type,
                instance='primary'
            ).set(success_value)
    
    def _collect_failover_metrics(self):
        """Collect failover operation metrics."""
        failover_logs_path = Path(self.config.config['paths']['failover_logs'])
        
        if failover_logs_path.exists():
            failover_files = list(failover_logs_path.glob('failover_metrics_*.json'))
            
            for metrics_file in failover_files[-3:]:  # Process last 3 files
                try:
                    with open(metrics_file, 'r') as f:
                        for line in f:
                            try:
                                metric_data = json.loads(line.strip())
                                self._process_failover_metric(metric_data)
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    self.logger.warning(f"Failed to read {metrics_file}: {e}")
    
    def _process_failover_metric(self, data: Dict[str, Any]):
        """Process individual failover metric entry."""
        operation = data.get('operation', '')
        status = data.get('status', '')
        duration = float(data.get('duration_seconds', 0))
        target_region = data.get('target_region', 'unknown')
        
        source_region = 'primary'  # Could be extracted from data
        instance = 'primary'
        
        if operation in ['failover', 'rollback']:
            self.metrics.failover_attempts_total.labels(
                source_region=source_region,
                target_region=target_region,
                instance=instance
            ).inc()
            
            if status == 'success':
                self.metrics.failover_success_total.labels(
                    source_region=source_region,
                    target_region=target_region,
                    instance=instance
                ).inc()
            
            if duration > 0:
                self.metrics.failover_duration_seconds.labels(
                    source_region=source_region,
                    target_region=target_region,
                    instance=instance
                ).observe(duration)
    
    def _collect_service_health_metrics(self):
        """Collect service health status metrics."""
        # This would check actual service health endpoints
        # For demonstration, using mock data
        
        services = [
            'fortress-postgres-primary',
            'fortress-redis-master',
            'fortress-core',
            'fortress-api',
            'fortress-smtp',
            'fortress-frontend',
            'nginx'
        ]
        
        for service in services:
            # Mock health status (in production, check actual endpoints)
            health_status = 1 if service != 'fortress-smtp' else 0  # Mock one unhealthy service
            
            self.metrics.service_health_status.labels(
                service_name=service,
                instance='primary'
            ).set(health_status)
    
    def _collect_system_metrics(self):
        """Collect system resource metrics."""
        # Disk usage for backup storage
        storage_paths = [
            '/var/lib/fortress/backups',
            '/var/lib/fortress/postgres',
            '/var/lib/fortress/redis'
        ]
        
        for path in storage_paths:
            if Path(path).exists():
                try:
                    disk_usage = psutil.disk_usage(path)
                    usage_percent = (disk_usage.used / disk_usage.total) * 100
                    
                    self.metrics.system_disk_usage_percent.labels(
                        mount_point=path,
                        instance='primary'
                    ).set(usage_percent)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to get disk usage for {path}: {e}")
        
        # Memory usage for backup processes
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                if 'fortress' in proc.info['name'].lower() or 'backup' in proc.info['name'].lower():
                    memory_bytes = proc.info['memory_info'].rss
                    
                    self.metrics.system_memory_usage_bytes.labels(
                        process=proc.info['name'],
                        instance='primary'
                    ).set(memory_bytes)
                    
        except Exception as e:
            self.logger.warning(f"Failed to collect memory metrics: {e}")

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Fortress Backup Metrics Exporter')
    parser.add_argument(
        '--config', 
        default='/etc/fortress/backup/metrics-config.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Load configuration
        config = Config(args.config)
        
        # Create and start metrics collector
        collector = FortressMetricsCollector(config)
        collector.start()
        
    except KeyboardInterrupt:
        logging.info("Received shutdown signal")
    except Exception as e:
        logging.error(f"Failed to start metrics exporter: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()