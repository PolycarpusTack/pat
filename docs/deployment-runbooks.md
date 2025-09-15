# 📋 Fortress Production Deployment Runbooks

**Version**: 1.0  
**Last Updated**: $(date)  
**Audience**: DevOps Engineers, Site Reliability Engineers, Production Support Teams

---

## 📑 Table of Contents

1. [Quick Reference](#-quick-reference)
2. [Standard Deployment Procedures](#-standard-deployment-procedures)
3. [Emergency Response Procedures](#-emergency-response-procedures)
4. [Troubleshooting Guide](#-troubleshooting-guide)
5. [Monitoring and Alerting](#-monitoring-and-alerting)
6. [Maintenance Procedures](#-maintenance-procedures)
7. [Security Procedures](#-security-procedures)
8. [Contact Information](#-contact-information)

---

## 🚀 Quick Reference

### Emergency Commands
```bash
# Emergency rollback
./scripts/fortress-rollback-automation.sh --strategy=immediate --reason="emergency"

# System status check
./scripts/fortress-deployment-monitor.sh --mode=single

# Health validation
./scripts/fortress-deployment-validator.sh --type=post-deployment --environment=production

# Production operations status
./scripts/fortress-production-operations.sh --operation=status
```

### Key File Locations
- **Main Deployment Script**: `/fortress-deploy-production.sh`
- **Validation Tools**: `/scripts/fortress-deployment-validator.sh`
- **Rollback Automation**: `/scripts/fortress-rollback-automation.sh`
- **Operations Tools**: `/scripts/fortress-production-operations.sh`
- **Monitoring**: `/scripts/fortress-deployment-monitor.sh`
- **Configuration**: `/config/production/`
- **Logs**: `/logs/production-deployment/`

### Critical Thresholds
- **Error Rate Critical**: >5%
- **Response Time Critical**: >2000ms
- **CPU Critical**: >85%
- **Memory Critical**: >90%
- **Disk Critical**: >90%

---

## 🚀 Standard Deployment Procedures

### SOP-001: Scheduled Production Deployment

**Purpose**: Standard process for planned production deployments during maintenance windows.

#### Prerequisites Checklist
- [ ] Change management ticket approved
- [ ] Code reviewed and approved
- [ ] All tests passing in CI/CD pipeline
- [ ] Security scans completed with no critical issues
- [ ] Staging deployment validated successfully
- [ ] Backup verification completed
- [ ] On-call team notified
- [ ] Rollback plan prepared
- [ ] Maintenance window scheduled
- [ ] Stakeholders notified

#### Pre-Deployment Steps

1. **Verify Environment State**
   ```bash
   # Check system health
   ./scripts/fortress-deployment-validator.sh \
     --type=pre-deployment \
     --environment=production \
     --strict
   
   # Verify backup systems
   ./scripts/fortress-production-operations.sh \
     --operation=backup \
     --backup-operation=validate
   ```

2. **Create Pre-Deployment Backup**
   ```bash
   ./scripts/fortress-production-operations.sh \
     --operation=backup \
     --backup-operation=create \
     --environment=production
   ```

3. **Prepare Monitoring**
   ```bash
   # Start extended monitoring
   ./scripts/fortress-deployment-monitor.sh \
     --mode=continuous \
     --duration=7200 \
     --webhook="$SLACK_WEBHOOK" &
   
   export MONITOR_PID=$!
   ```

#### Deployment Execution

4. **Execute Deployment**
   ```bash
   ./fortress-deploy-production.sh \
     --strategy=blue-green \
     --environment=production \
     --version="$VERSION" \
     --webhook="$SLACK_WEBHOOK"
   ```

5. **Monitor Deployment Progress**
   - Watch deployment logs in real-time
   - Monitor Slack notifications
   - Check Grafana dashboards
   - Verify service health endpoints

#### Post-Deployment Validation

6. **Comprehensive Validation**
   ```bash
   # Run full post-deployment validation
   ./scripts/fortress-deployment-validator.sh \
     --type=post-deployment \
     --environment=production \
     --timeout=600
   ```

7. **Business Function Testing**
   ```bash
   # Test critical business functions
   curl -f https://fortress.example.com/health
   curl -f https://fortress.example.com/api/v1/status
   curl -f https://fortress.example.com/metrics
   
   # Test SMTP functionality
   echo "Test email" | mail -s "Deployment Test" test@example.com
   ```

8. **Performance Validation**
   ```bash
   # Run performance validation for 30 minutes
   ./scripts/fortress-deployment-monitor.sh \
     --mode=continuous \
     --duration=1800 \
     --interval=30
   ```

#### Completion Steps

9. **Update Documentation**
   - Update deployment log
   - Record any issues encountered
   - Update monitoring baselines
   - Close change management ticket

10. **Notify Stakeholders**
    - Send deployment success notification
    - Update status page
    - Notify customer success team
    - Archive deployment artifacts

### SOP-002: Hotfix Deployment

**Purpose**: Expedited deployment process for critical security fixes and urgent bug fixes.

#### Acceleration Criteria
- Security vulnerability with CVSS > 7.0
- Production outage or critical functionality broken
- Data integrity issue
- Regulatory compliance requirement

#### Expedited Process

1. **Emergency Assessment**
   ```bash
   # Quick health check
   ./scripts/fortress-deployment-monitor.sh --mode=single
   
   # Identify impact scope
   kubectl get pods -n fortress --show-labels
   kubectl get events -n fortress --sort-by=.metadata.creationTimestamp
   ```

2. **Rapid Deployment**
   ```bash
   # Use rolling deployment for speed
   ./fortress-deploy-production.sh \
     --strategy=rolling \
     --environment=production \
     --version="$HOTFIX_VERSION" \
     --force-deployment \
     --webhook="$URGENT_WEBHOOK"
   ```

3. **Immediate Validation**
   ```bash
   # Fast validation focused on critical paths
   ./scripts/fortress-deployment-validator.sh \
     --type=post-deployment \
     --environment=production \
     --timeout=300
   ```

4. **Extended Monitoring**
   ```bash
   # Extended monitoring post-hotfix
   ./scripts/fortress-deployment-monitor.sh \
     --mode=continuous \
     --duration=3600 \
     --interval=15
   ```

---

## 🚨 Emergency Response Procedures

### ERP-001: Production Outage Response

**Trigger**: Critical services unavailable, error rates >10%, or complete system failure.

#### Immediate Response (0-5 minutes)

1. **Acknowledge Incident**
   ```bash
   # Create incident ticket
   echo "$(date): Production outage detected" >> /var/log/incidents.log
   
   # Page on-call engineer
   # Send high-priority alerts
   ```

2. **Quick Assessment**
   ```bash
   # Rapid system assessment
   ./scripts/fortress-deployment-monitor.sh --mode=single
   
   # Check recent deployments
   kubectl rollout history deployment -n fortress
   
   # Check system resources
   kubectl top nodes
   kubectl top pods -n fortress
   ```

3. **Triage Decision**
   - If recent deployment: Execute rollback (ERP-002)
   - If infrastructure issue: Scale/restart services (ERP-003)
   - If external dependency: Enable degraded mode (ERP-004)

#### Response Actions (5-15 minutes)

4. **Execute Primary Response**
   Based on triage decision, follow appropriate sub-procedure.

5. **Communication**
   ```bash
   # Status page update
   curl -X POST "$STATUS_PAGE_API" -d "status=investigating"
   
   # Stakeholder notification
   ./scripts/notify-stakeholders.sh --level=critical --message="Production incident - investigating"
   ```

#### Recovery and Follow-up (15+ minutes)

6. **Monitor Recovery**
   ```bash
   ./scripts/fortress-deployment-monitor.sh \
     --mode=continuous \
     --duration=3600 \
     --interval=10
   ```

7. **Document Incident**
   - Create detailed incident report
   - Identify root cause
   - Plan preventive measures
   - Schedule post-incident review

### ERP-002: Emergency Rollback

**Trigger**: Recent deployment causing production issues.

#### Immediate Rollback (0-3 minutes)

1. **Initiate Automatic Rollback**
   ```bash
   # Trigger automatic rollback system
   ./scripts/fortress-rollback-automation.sh \
     --strategy=auto-detect \
     --reason="production_incident" \
     --webhook="$EMERGENCY_WEBHOOK"
   ```

2. **Monitor Rollback Progress**
   ```bash
   # Watch rollback execution
   tail -f logs/rollback/rollback-*.log
   
   # Monitor service recovery
   watch kubectl get pods -n fortress
   ```

#### Fallback Procedures (3-10 minutes)

3. **If Automatic Rollback Fails**
   ```bash
   # Manual immediate rollback
   ./scripts/fortress-rollback-automation.sh \
     --strategy=immediate \
     --target-version="$LAST_KNOWN_GOOD_VERSION" \
     --force
   ```

4. **Database Rollback (if needed)**
   ```bash
   # Point-in-time database recovery
   ./scripts/fortress-production-operations.sh \
     --operation=backup \
     --backup-operation=restore \
     --backup-file="$BACKUP_FILE"
   ```

#### Validation and Recovery (10+ minutes)

5. **Validate Rollback Success**
   ```bash
   ./scripts/fortress-deployment-validator.sh \
     --type=post-deployment \
     --environment=production \
     --strict
   ```

6. **Extended Monitoring**
   ```bash
   # Monitor system stability
   ./scripts/fortress-deployment-monitor.sh \
     --mode=continuous \
     --duration=7200 \
     --interval=30
   ```

### ERP-003: Infrastructure Scaling Response

**Trigger**: Resource exhaustion, high load, or capacity issues.

#### Immediate Scaling (0-5 minutes)

1. **Emergency Resource Scaling**
   ```bash
   # Scale critical services
   kubectl scale deployment fortress-api -n fortress --replicas=6
   kubectl scale deployment fortress-smtp -n fortress --replicas=4
   
   # Enable burst scaling
   kubectl patch hpa fortress-api -n fortress -p '{"spec":{"maxReplicas":10}}'
   ```

2. **Check Node Capacity**
   ```bash
   kubectl describe nodes
   kubectl top nodes
   
   # Add nodes if needed (cloud auto-scaling)
   aws eks update-nodegroup-config \
     --cluster-name fortress-production \
     --nodegroup-name fortress-workers \
     --scaling-config minSize=3,maxSize=10,desiredSize=6
   ```

#### Performance Optimization (5-15 minutes)

3. **Database Optimization**
   ```bash
   # Check database performance
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c "SELECT * FROM pg_stat_activity;"
   
   # Optimize queries if needed
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c "ANALYZE;"
   ```

4. **Cache Optimization**
   ```bash
   # Check Redis status
   kubectl exec -it redis-0 -n fortress -- redis-cli info
   
   # Clear cache if needed
   kubectl exec -it redis-0 -n fortress -- redis-cli flushdb
   ```

### ERP-004: Degraded Mode Activation

**Trigger**: External dependency failures or partial system degradation.

#### Enable Degraded Operation

1. **Activate Circuit Breakers**
   ```bash
   # Enable degraded mode configuration
   kubectl patch configmap fortress-config -n fortress \
     -p '{"data":{"degraded_mode":"true"}}'
   
   # Restart services to pick up config
   kubectl rollout restart deployment/fortress-api -n fortress
   ```

2. **Disable Non-Critical Features**
   ```bash
   # Disable resource-intensive features
   kubectl scale deployment fortress-workflows -n fortress --replicas=1
   
   # Enable minimal feature set
   kubectl patch configmap fortress-config -n fortress \
     -p '{"data":{"features":"minimal"}}'
   ```

---

## 🔧 Troubleshooting Guide

### TSG-001: Deployment Stuck or Failed

**Symptoms**: Deployment process hangs, pods stuck in pending state, or deployment timeout.

#### Diagnosis Steps

1. **Check Pod Status**
   ```bash
   kubectl get pods -n fortress
   kubectl describe pods -n fortress
   
   # Check events
   kubectl get events -n fortress --sort-by=.metadata.creationTimestamp
   ```

2. **Check Resource Constraints**
   ```bash
   # Node resources
   kubectl top nodes
   kubectl describe nodes
   
   # Resource quotas
   kubectl describe resourcequota -n fortress
   ```

3. **Check Image Pull Issues**
   ```bash
   # Check image pull secrets
   kubectl get secrets -n fortress
   
   # Test image accessibility
   docker pull fortress/fortress-api:latest
   ```

#### Resolution Actions

4. **Resource Issues**
   ```bash
   # Scale down non-critical services
   kubectl scale deployment fortress-workflows -n fortress --replicas=0
   
   # Add more nodes
   # (Cloud-specific node scaling commands)
   ```

5. **Image Issues**
   ```bash
   # Update image pull secrets
   kubectl create secret docker-registry fortress-registry \
     --docker-server=ghcr.io \
     --docker-username="$GITHUB_USER" \
     --docker-password="$GITHUB_TOKEN" \
     -n fortress
   
   # Patch deployments to use secret
   kubectl patch deployment fortress-api -n fortress \
     -p '{"spec":{"template":{"spec":{"imagePullSecrets":[{"name":"fortress-registry"}]}}}}'
   ```

### TSG-002: Service Health Check Failures

**Symptoms**: Health endpoints returning errors, services marked as unhealthy.

#### Diagnosis Steps

1. **Check Service Status**
   ```bash
   # Port forward and test locally
   kubectl port-forward -n fortress service/fortress-api 8025:8025 &
   curl -v http://localhost:8025/health
   
   # Check service logs
   kubectl logs -n fortress -l app=fortress-api --tail=100
   ```

2. **Check Dependencies**
   ```bash
   # Database connectivity
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c '\l'
   
   # Redis connectivity
   kubectl exec -it redis-0 -n fortress -- \
     redis-cli ping
   ```

#### Resolution Actions

3. **Restart Unhealthy Services**
   ```bash
   kubectl rollout restart deployment/fortress-api -n fortress
   
   # Force pod recreation
   kubectl delete pods -n fortress -l app=fortress-api
   ```

4. **Fix Configuration Issues**
   ```bash
   # Check and update configuration
   kubectl get configmap fortress-config -n fortress -o yaml
   
   # Update if needed
   kubectl patch configmap fortress-config -n fortress \
     --type merge -p '{"data":{"database_url":"updated_url"}}'
   ```

### TSG-003: Performance Degradation

**Symptoms**: High response times, increased error rates, slow processing.

#### Diagnosis Steps

1. **Check System Resources**
   ```bash
   # Pod resource usage
   kubectl top pods -n fortress
   
   # Node resource usage
   kubectl top nodes
   ```

2. **Check Application Metrics**
   ```bash
   # Response time analysis
   ./scripts/fortress-deployment-monitor.sh --mode=single
   
   # Database performance
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c "SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
   ```

#### Resolution Actions

3. **Scale Resources**
   ```bash
   # Horizontal scaling
   kubectl scale deployment fortress-api -n fortress --replicas=5
   
   # Vertical scaling (update resource limits)
   kubectl patch deployment fortress-api -n fortress \
     -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress-api","resources":{"limits":{"cpu":"2","memory":"4Gi"}}}]}}}}'
   ```

4. **Optimize Database**
   ```bash
   # Database maintenance
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c "VACUUM ANALYZE;"
   
   # Update statistics
   kubectl exec -it postgres-0 -n fortress -- \
     psql -U fortress -c "ANALYZE;"
   ```

### TSG-004: Certificate Issues

**Symptoms**: SSL/TLS errors, certificate expiry warnings, HTTPS connection failures.

#### Diagnosis Steps

1. **Check Certificate Status**
   ```bash
   # Check certificate expiry
   ./scripts/fortress-production-operations.sh \
     --operation=ssl \
     --ssl-operation=check
   
   # Manual certificate check
   echo | openssl s_client -servername fortress.example.com -connect fortress.example.com:443 -showcerts
   ```

2. **Check Kubernetes Certificates**
   ```bash
   # Check certificate resources
   kubectl get certificates -n fortress
   kubectl describe certificates -n fortress
   
   # Check cert-manager status
   kubectl get pods -n cert-manager
   ```

#### Resolution Actions

3. **Renew Certificates**
   ```bash
   # Automatic renewal
   ./scripts/fortress-production-operations.sh \
     --operation=ssl \
     --ssl-operation=renew
   ```

4. **Manual Certificate Update**
   ```bash
   # Force certificate renewal
   kubectl delete secret fortress-tls -n fortress
   kubectl delete certificate fortress-tls -n fortress
   
   # Recreate certificate
   kubectl apply -f k8s/certificates.yaml
   ```

---

## 📊 Monitoring and Alerting

### MON-001: Monitoring Dashboard Setup

#### Grafana Dashboard Configuration

1. **Access Grafana**
   ```bash
   kubectl port-forward -n fortress service/grafana 3000:3000
   # Access http://localhost:3000 (admin/admin)
   ```

2. **Import Fortress Dashboards**
   ```bash
   # Apply dashboard configurations
   kubectl apply -f config/monitoring/grafana-dashboards.yaml
   
   # Verify dashboard import
   curl -s http://admin:admin@localhost:3000/api/dashboards/home
   ```

#### Key Metrics to Monitor

- **Service Health**: Pod status, readiness probes, liveness probes
- **Performance**: Response times, throughput, error rates
- **Resources**: CPU, memory, disk, network usage
- **Business**: Email processing rates, API usage, queue depths
- **Infrastructure**: Node health, cluster capacity, storage usage

### MON-002: Alert Configuration

#### Prometheus Alerting Rules

1. **Deploy Alert Rules**
   ```bash
   kubectl apply -f config/monitoring/prometheus-alerts.yaml
   ```

2. **Configure Alertmanager**
   ```bash
   kubectl apply -f config/monitoring/alertmanager-config.yaml
   
   # Verify configuration
   kubectl logs -n fortress alertmanager-0
   ```

#### Critical Alert Definitions

- **Service Down**: Any service with 0 ready replicas
- **High Error Rate**: Error rate > 5% for 5 minutes
- **High Response Time**: 95th percentile > 2000ms for 10 minutes
- **Resource Exhaustion**: CPU > 85% or Memory > 90% for 15 minutes
- **Disk Space**: Disk usage > 90%

### MON-003: Incident Response Integration

#### PagerDuty Integration

1. **Configure PagerDuty Service**
   ```bash
   # Update Alertmanager configuration with PagerDuty webhook
   kubectl patch secret alertmanager-config -n fortress \
     -p '{"data":{"alertmanager.yml":"<base64-encoded-config>"}}'
   ```

2. **Test Alert Routing**
   ```bash
   # Generate test alert
   ./scripts/fortress-deployment-monitor.sh \
     --mode=test \
     --webhook="$PAGERDUTY_WEBHOOK"
   ```

---

## 🔧 Maintenance Procedures

### MAINT-001: Scheduled Maintenance

#### Pre-Maintenance Checklist
- [ ] Maintenance window approved and communicated
- [ ] Current system backup verified
- [ ] Rollback plan prepared
- [ ] Team resources allocated
- [ ] Customer notification sent

#### Maintenance Execution

1. **System Backup**
   ```bash
   ./scripts/fortress-production-operations.sh \
     --operation=backup \
     --backup-operation=create
   ```

2. **Maintenance Tasks**
   ```bash
   # System maintenance
   ./scripts/fortress-production-operations.sh \
     --operation=maintenance \
     --maintenance-operation=all
   
   # Security updates
   ./scripts/fortress-production-operations.sh \
     --operation=maintenance \
     --maintenance-operation=security
   ```

3. **Post-Maintenance Validation**
   ```bash
   ./scripts/fortress-deployment-validator.sh \
     --type=post-deployment \
     --environment=production
   ```

### MAINT-002: Certificate Renewal

#### Automated Certificate Renewal

1. **Check Certificate Status**
   ```bash
   ./scripts/fortress-production-operations.sh \
     --operation=ssl \
     --ssl-operation=check
   ```

2. **Renew Certificates**
   ```bash
   ./scripts/fortress-production-operations.sh \
     --operation=ssl \
     --ssl-operation=renew
   ```

3. **Validate Renewal**
   ```bash
   # Test certificate validity
   echo | openssl s_client -servername fortress.example.com -connect fortress.example.com:443 2>/dev/null | openssl x509 -noout -dates
   ```

### MAINT-003: Secret Rotation

#### Regular Secret Rotation

1. **Rotate Secrets**
   ```bash
   ./scripts/fortress-production-operations.sh \
     --operation=secrets \
     --secret-operation=rotate
   ```

2. **Verify Secret Updates**
   ```bash
   # Check secret age
   ./scripts/fortress-production-operations.sh \
     --operation=secrets \
     --secret-operation=check
   
   # Test service functionality
   ./scripts/fortress-deployment-validator.sh \
     --type=post-deployment \
     --environment=production
   ```

---

## 🛡️ Security Procedures

### SEC-001: Security Incident Response

#### Immediate Response

1. **Assess Security Impact**
   ```bash
   # Run security audit
   ./fortress_security_audit.sh
   
   # Check for unauthorized access
   kubectl get events -n fortress | grep -i "fail\|error\|unauthorized"
   ```

2. **Isolate Affected Components**
   ```bash
   # Network isolation if needed
   kubectl patch networkpolicy default-deny -n fortress \
     -p '{"spec":{"ingress":[],"egress":[]}}'
   
   # Scale down affected services
   kubectl scale deployment suspicious-service -n fortress --replicas=0
   ```

3. **Evidence Collection**
   ```bash
   # Collect logs
   kubectl logs -n fortress --all-containers=true --since=24h > incident-logs.txt
   
   # Export system state
   kubectl get all -n fortress -o yaml > incident-state.yaml
   ```

### SEC-002: Security Hardening

#### Regular Security Tasks

1. **Update Security Policies**
   ```bash
   # Apply security policies
   kubectl apply -f config/security/network-policies.yaml
   kubectl apply -f config/security/pod-security-policies.yaml
   ```

2. **Vulnerability Scanning**
   ```bash
   # Scan container images
   trivy image fortress/fortress-api:latest
   
   # Scan Kubernetes configuration
   kubectl apply -f config/security/security-scan.yaml
   ```

---

## 📞 Contact Information

### Emergency Contacts

| Role | Contact | Phone | Email |
|------|---------|-------|-------|
| **Primary On-Call** | DevOps Engineer | +1-xxx-xxx-xxxx | oncall@fortress.example.com |
| **Secondary On-Call** | SRE Lead | +1-xxx-xxx-xxxx | sre-lead@fortress.example.com |
| **Security Team** | Security Engineer | +1-xxx-xxx-xxxx | security@fortress.example.com |
| **Engineering Manager** | Engineering Manager | +1-xxx-xxx-xxxx | eng-manager@fortress.example.com |

### Escalation Matrix

| Severity | Initial Contact | Escalation Time | Escalation Contact |
|----------|----------------|-----------------|-------------------|
| **P0 - Critical** | Primary On-Call | 15 minutes | SRE Lead + Eng Manager |
| **P1 - High** | Primary On-Call | 30 minutes | SRE Lead |
| **P2 - Medium** | Primary On-Call | 2 hours | SRE Lead |
| **P3 - Low** | Ticket System | Next Business Day | Team Assignment |

### Communication Channels

- **Slack**: #fortress-operations, #fortress-alerts
- **Email**: fortress-ops@example.com
- **PagerDuty**: https://fortress.pagerduty.com
- **Status Page**: https://status.fortress.example.com
- **Monitoring**: https://monitoring.fortress.example.com

### External Vendors

| Service | Contact | Support Level | Phone |
|---------|---------|---------------|-------|
| **AWS Support** | Enterprise Support | 24/7 | +1-xxx-xxx-xxxx |
| **GitHub Support** | Enterprise Support | Business Hours | support@github.com |
| **Datadog Support** | Premium Support | 24/7 | support@datadog.com |

---

## 📚 Additional Resources

### Documentation Links
- [Fortress Architecture Overview](../FORTRESS_ARCHITECTURE.md)
- [Security Implementation Guide](../FORTRESS_SECURITY_IMPLEMENTATION.md)
- [Disaster Recovery Procedures](../disaster-recovery/README.md)
- [Monitoring Configuration Guide](../monitoring/README.md)

### Training Materials
- Kubernetes Operations Training
- Incident Response Procedures
- Security Best Practices
- Monitoring and Alerting Setup

### Tools and Utilities
- kubectl cheat sheet
- Docker troubleshooting guide
- Prometheus query examples
- Grafana dashboard templates

---

**Document Control**
- **Version**: 1.0
- **Approved By**: SRE Team Lead
- **Review Date**: Quarterly
- **Next Review**: $(date -d '+3 months')

---

*This document is part of the Fortress Production Operations suite. For updates or corrections, please create a pull request or contact the DevOps team.*