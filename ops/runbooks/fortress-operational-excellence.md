# 🏰 Pat Fortress Operational Excellence Guide

## Overview

This guide provides comprehensive operational procedures for maintaining and monitoring Pat Fortress in production environments. It covers monitoring, alerting, incident response, and maintenance procedures to ensure 99.9% uptime and optimal performance.

## Table of Contents

1. [Monitoring & Observability](#monitoring--observability)
2. [Alerting & Incident Response](#alerting--incident-response)
3. [Performance Management](#performance-management)
4. [Security Operations](#security-operations)
5. [Maintenance Procedures](#maintenance-procedures)
6. [Disaster Recovery](#disaster-recovery)
7. [Troubleshooting Guide](#troubleshooting-guide)

## Monitoring & Observability

### Key Performance Indicators (KPIs)

#### Service Availability
- **Target**: 99.9% uptime (< 8.77 hours downtime per year)
- **Measurement**: Health check success rate across all services
- **Alert Threshold**: < 99.5% over 5-minute period

#### Response Time
- **Target**: 95th percentile < 500ms for API calls
- **Measurement**: HTTP request duration histograms
- **Alert Threshold**: 95th percentile > 2 seconds for 5 minutes

#### Email Processing
- **Target**: < 50ms average processing time per email
- **Measurement**: Email processing duration metrics
- **Alert Threshold**: > 100ms average for 10 minutes

#### Error Rate
- **Target**: < 0.1% error rate for all requests
- **Measurement**: HTTP 5xx errors / total requests
- **Alert Threshold**: > 1% error rate for 5 minutes

### Monitoring Stack

```yaml
# Prometheus + Grafana + AlertManager
Metrics Collection: Prometheus (15s scrape interval)
Visualization: Grafana dashboards
Alerting: AlertManager with Slack/PagerDuty integration
Log Aggregation: ELK stack (Elasticsearch, Logstash, Kibana)
Tracing: Jaeger for distributed tracing
```

### Critical Dashboards

1. **Fortress Overview Dashboard**
   - Service health status matrix
   - Key business metrics (emails processed, tenants active)
   - Infrastructure resource utilization
   - Error rate trends

2. **SMTP Performance Dashboard**
   - Connection pool status
   - Email processing throughput
   - Queue sizes and processing delays
   - Protocol-specific metrics (STARTTLS usage, authentication success rate)

3. **API Performance Dashboard**
   - Request rate and response times
   - Endpoint-specific performance metrics
   - Rate limiting status
   - Authentication metrics

4. **Infrastructure Dashboard**
   - CPU, memory, disk utilization
   - Network throughput
   - Container resource usage
   - Database performance metrics

### Log Management

```bash
# Log Levels and Retention
DEBUG: Development only (not in production)
INFO: Business events, successful operations (7 days)
WARN: Recoverable issues, degraded performance (30 days)
ERROR: Service errors, failed operations (90 days)
FATAL: Critical system failures (1 year)

# Structured Logging Format
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "service": "fortress-smtp",
  "component": "email-processor",
  "message": "Email processed successfully",
  "tenant_id": "tenant-123",
  "email_id": "email-456",
  "processing_time_ms": 42,
  "trace_id": "trace-789"
}
```

## Alerting & Incident Response

### Alert Severity Levels

#### Critical (P1)
- **Response Time**: 5 minutes
- **Escalation**: Immediate PagerDuty notification
- **Examples**: Service completely down, data corruption, security breach
- **Actions**: Page on-call engineer, create war room if needed

#### High (P2)
- **Response Time**: 30 minutes
- **Escalation**: Slack notification + email
- **Examples**: High error rates, performance degradation, partial outage
- **Actions**: Investigate and resolve within 2 hours

#### Warning (P3)
- **Response Time**: 2 hours during business hours
- **Escalation**: Slack notification
- **Examples**: Resource warnings, minor performance issues
- **Actions**: Schedule investigation and resolution

#### Info (P4)
- **Response Time**: Next business day
- **Escalation**: Daily digest email
- **Examples**: Maintenance reminders, capacity planning alerts
- **Actions**: Add to backlog for routine handling

### Incident Response Playbook

#### 1. Incident Detection
```bash
# Automated detection sources:
- Prometheus alerts
- Health check failures
- Log error patterns
- User reports
- Synthetic monitoring failures

# Manual detection:
- Performance degradation reports
- Customer complaints
- Third-party service notifications
```

#### 2. Initial Response (0-5 minutes)
1. **Acknowledge** the alert in monitoring system
2. **Assess** impact and severity using runbooks
3. **Create** incident ticket with initial details
4. **Notify** relevant team members
5. **Start** timer for resolution SLA

#### 3. Investigation & Diagnosis (5-30 minutes)
1. **Check** service status dashboard
2. **Review** recent deployments and changes
3. **Analyze** logs and metrics for root cause
4. **Identify** affected components and users
5. **Estimate** impact and create communication plan

#### 4. Resolution & Recovery
1. **Implement** immediate mitigation if possible
2. **Execute** recovery procedures from runbooks
3. **Monitor** system recovery and metrics
4. **Communicate** status updates to stakeholders
5. **Verify** full service restoration

#### 5. Post-Incident Activities
1. **Conduct** post-incident review (PIR)
2. **Document** root cause and timeline
3. **Create** action items for prevention
4. **Update** runbooks and monitoring
5. **Share** learnings with team

### Runbook Structure

Each runbook follows this template:

```markdown
# Alert Name: [Specific Alert Title]

## Severity: [Critical/High/Warning/Info]

## Description
Brief description of what this alert indicates

## Impact
What this means for users and business operations

## Investigation Steps
1. Check X dashboard
2. Review Y logs
3. Validate Z metrics
4. Test A functionality

## Resolution Steps
1. If condition X, then do Y
2. If condition A, then do B
3. Contact team Z if steps 1-2 fail

## Prevention
Long-term measures to prevent recurrence

## Related Links
- Dashboard: [URL]
- Logs: [URL]
- Documentation: [URL]
```

## Performance Management

### Capacity Planning

#### Current Baseline (Production)
```yaml
SMTP Server:
  Connections: 100 concurrent
  Throughput: 1000 emails/minute
  Memory: 2GB average
  CPU: 40% average

API Server:
  Requests: 500 req/sec
  Response Time: 150ms p95
  Memory: 1GB average
  CPU: 30% average

Database:
  Connections: 25 active
  Query Time: 50ms average
  Storage: 100GB
  Growth: 10GB/month
```

#### Scaling Thresholds
- **Scale Up**: CPU > 70% for 10 minutes
- **Scale Down**: CPU < 30% for 30 minutes
- **Maximum Instances**: 20 per service
- **Minimum Instances**: 2 per service (HA requirement)

#### Performance Optimization Checklist

**Weekly Performance Review:**
- [ ] Check 95th percentile response times
- [ ] Review database slow query log
- [ ] Analyze memory usage trends
- [ ] Verify cache hit rates
- [ ] Check connection pool utilization

**Monthly Capacity Assessment:**
- [ ] Project resource needs for next quarter
- [ ] Review auto-scaling effectiveness
- [ ] Analyze cost vs. performance trends
- [ ] Plan for traffic growth patterns
- [ ] Update capacity baselines

### Load Testing

```bash
# Regular load testing schedule
Weekly: Smoke tests (2x normal load for 10 minutes)
Monthly: Stress tests (5x normal load for 30 minutes)
Quarterly: Spike tests (10x load for 5 minutes)
Pre-deployment: Regression tests (baseline scenarios)

# Load testing tools and scenarios
Tool: k6 for HTTP load testing
Tool: smtp-load-tester for SMTP testing
Scenarios: Normal, peak, spike, sustained load
Metrics: Response time, error rate, throughput
```

## Security Operations

### Security Monitoring

#### Threat Detection
- Failed authentication attempts > 20/5min from same IP
- Unusual traffic patterns (geography, volume, timing)
- Suspicious email content patterns
- Plugin execution anomalies
- Database access pattern deviations

#### Security Metrics
```yaml
Authentication:
  Failed logins per hour: < 100
  Account lockouts per day: < 10
  Suspicious IPs blocked: Monitor trend

Network Security:
  DDoS protection triggered: Alert immediately
  Rate limiting activated: Monitor patterns
  Geographic anomalies: Flag unusual countries

Data Security:
  Encryption key rotations: Monthly
  Certificate expirations: 30-day warning
  Backup integrity checks: Daily
```

### Security Incident Response

#### Data Breach Response (P1 - Critical)
1. **Immediate Actions (0-1 hour)**:
   - Isolate affected systems
   - Preserve evidence
   - Notify security team
   - Assess scope of breach

2. **Investigation (1-4 hours)**:
   - Forensic analysis
   - Identify compromised data
   - Determine attack vector
   - Document timeline

3. **Containment (4-24 hours)**:
   - Patch security vulnerabilities
   - Revoke compromised credentials
   - Update security controls
   - Monitor for continued activity

4. **Recovery & Communication**:
   - Restore services securely
   - Notify affected customers
   - Report to authorities if required
   - Update security procedures

### Security Maintenance

#### Weekly Security Tasks
- [ ] Review security alerts and incidents
- [ ] Update threat intelligence feeds
- [ ] Check for new CVEs affecting our stack
- [ ] Validate backup encryption
- [ ] Review access logs for anomalies

#### Monthly Security Tasks
- [ ] Security patch deployment
- [ ] Access review and cleanup
- [ ] Penetration testing results review
- [ ] Security training completion check
- [ ] Incident response drill

## Maintenance Procedures

### Planned Maintenance Windows

#### Weekly Maintenance (Sundays 2-4 AM UTC)
- Security patch application
- Database maintenance (VACUUM, ANALYZE)
- Log rotation and cleanup
- Configuration updates
- Performance monitoring review

#### Monthly Maintenance (First Sunday 1-5 AM UTC)
- Major dependency updates
- Database schema changes
- Infrastructure upgrades
- Disaster recovery testing
- Capacity scaling adjustments

### Deployment Procedures

#### Zero-Downtime Deployment Process
1. **Pre-deployment Checks**:
   - All tests passing
   - Security scan clean
   - Performance regression check
   - Database migration validation

2. **Blue-Green Deployment**:
   - Deploy to green environment
   - Run smoke tests on green
   - Switch traffic gradually (10%, 50%, 100%)
   - Monitor metrics during switch
   - Keep blue environment as rollback

3. **Post-deployment Verification**:
   - Health checks passing
   - Key metrics within normal ranges
   - Error rates < baseline
   - Performance metrics acceptable

4. **Rollback Procedure**:
   - Trigger: Error rate > 5x baseline
   - Action: Immediate traffic switch to blue
   - Timeline: < 2 minutes for rollback
   - Communication: Auto-notify stakeholders

### Database Maintenance

#### Daily Tasks (Automated)
```sql
-- Connection monitoring
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

-- Lock monitoring
SELECT count(*) FROM pg_locks WHERE NOT GRANTED;

-- Long-running queries
SELECT query, query_start FROM pg_stat_activity 
WHERE state = 'active' AND query_start < now() - interval '5 minutes';
```

#### Weekly Tasks
```sql
-- Update statistics
ANALYZE;

-- Check for unused indexes
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats WHERE schemaname = 'public';

-- Vacuum maintenance
VACUUM (VERBOSE, ANALYZE);
```

#### Monthly Tasks
```sql
-- Reindex heavily used indexes
REINDEX INDEX CONCURRENTLY idx_emails_created_at;
REINDEX INDEX CONCURRENTLY idx_emails_tenant_id;

-- Check table bloat
SELECT schemaname, tablename, attname, n_dead_tup 
FROM pg_stat_user_tables WHERE n_dead_tup > 1000;
```

## Disaster Recovery

### Recovery Time Objectives (RTO) & Recovery Point Objectives (RPO)

| Component | RTO | RPO | Recovery Method |
|-----------|-----|-----|----------------|
| SMTP Service | 5 minutes | 1 minute | Auto-failover |
| API Service | 5 minutes | 1 minute | Auto-failover |
| Database | 30 minutes | 5 minutes | Point-in-time recovery |
| Plugin System | 15 minutes | 10 minutes | Restart + reload |
| Full System | 2 hours | 15 minutes | Complete rebuild |

### Backup Strategy

#### Database Backups
- **Frequency**: Continuous WAL archiving + daily full backups
- **Retention**: 30 days full backups, 7 days WAL files
- **Testing**: Weekly restore test to staging environment
- **Encryption**: AES-256 encryption at rest and in transit

#### Configuration Backups
- **Frequency**: Every configuration change
- **Storage**: Git repository with encrypted secrets
- **Testing**: Monthly restoration drill
- **Versioning**: Tagged releases for rollback points

#### Data Validation
```bash
# Daily backup validation
#!/bin/bash
BACKUP_FILE="/backups/fortress-$(date +%Y%m%d).sql.gz"
TEST_DB="fortress_restore_test"

# Create test database
createdb $TEST_DB

# Restore from backup
gunzip -c $BACKUP_FILE | psql $TEST_DB

# Validate critical tables
psql $TEST_DB -c "SELECT count(*) FROM emails WHERE created_at > now() - interval '24 hours';"
psql $TEST_DB -c "SELECT count(*) FROM plugins WHERE status = 'active';"

# Cleanup
dropdb $TEST_DB

echo "Backup validation completed at $(date)"
```

### Disaster Scenarios & Response

#### Scenario 1: Single Service Failure
**Detection**: Health check failure, metrics drop
**Response**: Auto-failover to healthy instance
**Timeline**: < 5 minutes automatic recovery
**Manual Steps**: Investigate root cause, replace failed instance

#### Scenario 2: Database Corruption
**Detection**: Database connection errors, data inconsistencies
**Response**: Switch to read replica, restore from backup
**Timeline**: 30 minutes to restore service
**Manual Steps**: Full database recovery, data integrity verification

#### Scenario 3: Complete Infrastructure Loss
**Detection**: All services unreachable, infrastructure alerts
**Response**: Activate disaster recovery site
**Timeline**: 2 hours to full service restoration
**Manual Steps**: Rebuild from infrastructure as code, restore data from backups

## Troubleshooting Guide

### Common Issues & Solutions

#### High Memory Usage
```bash
# Investigation
docker stats  # Check container memory usage
ps aux --sort=-%mem | head -10  # Check process memory usage

# Common causes
- Memory leaks in plugin code
- Large email attachments being processed
- Inefficient database queries loading large datasets
- Cache not being properly cleared

# Solutions
- Restart affected service
- Review and optimize plugin code
- Implement email size limits
- Add database query optimization
- Configure proper cache expiration
```

#### Database Connection Pool Exhaustion
```bash
# Investigation
SELECT count(*), state FROM pg_stat_activity GROUP BY state;

# Common causes
- Long-running queries holding connections
- Application not releasing connections properly
- Connection pool size too small for load

# Solutions
- Kill long-running queries: SELECT pg_terminate_backend(pid);
- Increase connection pool size temporarily
- Review application connection handling
- Implement connection timeout settings
```

#### SMTP Performance Issues
```bash
# Investigation
tail -f /var/log/fortress/smtp.log | grep "slow"
netstat -an | grep :1025 | wc -l  # Check connection count

# Common causes
- Too many concurrent connections
- Slow email processing plugins
- Network latency to downstream services
- Large email attachments

# Solutions
- Implement connection rate limiting
- Optimize plugin performance
- Add caching for repeated operations
- Implement async processing for large emails
```

#### Plugin System Failures
```bash
# Investigation
grep "plugin_error" /var/log/fortress/plugins.log
curl -s http://fortress:8030/metrics | grep plugin

# Common causes
- Plugin code errors or exceptions
- Resource constraints (memory, CPU)
- Plugin dependencies unavailable
- Configuration issues

# Solutions
- Review plugin logs for specific errors
- Restart plugin system: POST /plugins/restart
- Disable problematic plugin temporarily
- Update plugin configuration
- Check plugin resource limits
```

### Emergency Contact Information

```yaml
On-Call Engineer (24/7): +1-555-ONCALL
Security Team: security@fortress.example.com
Infrastructure Team: ops@fortress.example.com
Development Team: dev@fortress.example.com

Escalation Matrix:
L1: On-call engineer (5 min response)
L2: Team lead (15 min response)  
L3: Engineering manager (30 min response)
L4: VP Engineering (1 hour response)

External Contacts:
Cloud Provider Support: [Provider-specific number]
Security Vendor: [Vendor support line]
Monitoring Service: [Service provider support]
```

### Useful Commands Reference

```bash
# Service status
docker-compose ps
systemctl status fortress-*

# Log tailing
tail -f /var/log/fortress/*.log
docker logs -f fortress-smtp

# Metrics checking
curl -s http://localhost:9090/metrics | grep fortress
prometheus-query 'fortress_emails_total'

# Database queries
psql -h localhost -U fortress -d fortress_production
SELECT * FROM pg_stat_activity WHERE state = 'active';

# Network debugging
netstat -tulpn | grep :1025
tcpdump -i eth0 port 1025

# Performance monitoring
top -p $(pgrep -f fortress)
iostat -x 5
sar -u 5 5
```

---

## Document Maintenance

**Last Updated**: 2024-01-15  
**Next Review**: 2024-04-15  
**Owner**: Fortress Operations Team  
**Approvers**: Engineering Manager, Security Lead  

**Change Log**:
- 2024-01-15: Initial version with comprehensive operational procedures
- 2024-01-10: Added security incident response procedures
- 2024-01-05: Updated monitoring thresholds and KPIs