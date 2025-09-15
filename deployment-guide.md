# Pat Email Testing Platform - Production Deployment Guide

## Overview

This guide covers the complete deployment of the Pat email testing platform with all advanced features including:

- **Serverless SMTP** with Lambda functions
- **Event-driven architecture** using Kafka and EventBridge
- **GraphQL API** with real-time subscriptions
- **JWT Authentication** with RBAC
- **AI-powered email analysis** with sentiment, spam, and anomaly detection
- **Workflow engine** for automated email processing
- **Monitoring and observability** with Prometheus and Grafana
- **Plugin system** with V8 isolation
- **Next.js frontend** with Material-UI components

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway    │    │   SMTP Server   │
│   (Next.js)     │    │   (GraphQL)      │    │   (Go/Lambda)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────────┐
                    │     Event Bus           │
                    │   (Kafka/EventBridge)   │
                    └─────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Workflow       │    │   AI Analysis    │    │   Plugin        │
│  Engine         │    │   Service        │    │   Runtime       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────────┐
                    │     Data Layer          │
                    │  PostgreSQL + Redis     │
                    └─────────────────────────┘
```

## Prerequisites

### System Requirements

- **OS**: Ubuntu 20.04+ / CentOS 8+ / Amazon Linux 2
- **CPU**: 4+ cores (8+ recommended for production)
- **Memory**: 8GB+ RAM (16GB+ recommended)
- **Storage**: 100GB+ SSD storage
- **Network**: Stable internet connection with ports 80, 443, 1025 accessible

### Required Software

- Docker 20.10+
- Docker Compose 2.0+
- Node.js 18+ (for local development)
- Go 1.21+ (for local development)

### AWS Requirements (for serverless components)

- AWS Account with appropriate permissions
- AWS CLI configured
- Terraform 1.5+ for infrastructure provisioning

## Quick Start (Docker Compose)

### 1. Clone and Configure

```bash
# Clone the repository
git clone https://github.com/alexandria/pat-plugin.git
cd pat-plugin

# Copy environment template
cp .env.example .env.production

# Edit configuration
nano .env.production
```

### 2. Environment Configuration

```bash
# Database Configuration
POSTGRES_DB=pat_production
POSTGRES_USER=pat_user
POSTGRES_PASSWORD=your_secure_password_here

# Redis Configuration
REDIS_PASSWORD=your_redis_password_here

# JWT Configuration
JWT_SECRET=your_jwt_secret_256_bits_minimum
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# API Configuration
API_PORT=8025
SMTP_PORT=1025
FRONTEND_PORT=3000

# CORS Configuration
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Frontend Configuration
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
NEXT_PUBLIC_WS_URL=wss://api.yourdomain.com

# Monitoring
GRAFANA_ADMIN_PASSWORD=your_grafana_password

# Plugin System
MAX_PLUGIN_MEMORY=128
MAX_PLUGIN_EXECUTION_TIME=30000

# Workflow Engine
MAX_CONCURRENT_WORKFLOWS=100
```

### 3. Generate JWT Keys

```bash
# Generate RSA key pair for JWT signing
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Convert to environment variable format
echo "JWT_PRIVATE_KEY=\"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' private_key.pem)\""
echo "JWT_PUBLIC_KEY=\"$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' public_key.pem)\""
```

### 4. SSL Certificate Setup

```bash
# For production, use Let's Encrypt
sudo certbot certonly --standalone -d yourdomain.com -d api.yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./ssl/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./ssl/
sudo chown $(whoami):$(whoami) ./ssl/*.pem
```

### 5. Deploy Services

```bash
# Build and start all services
docker-compose -f docker-compose.production.yml --env-file .env.production up -d

# Check service health
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f pat-api
```

## AWS Serverless Deployment

### 1. Infrastructure Setup

```bash
# Initialize Terraform
cd terraform/
terraform init

# Plan deployment
terraform plan -var-file="production.tfvars"

# Apply infrastructure
terraform apply -var-file="production.tfvars"
```

### 2. Deploy Lambda Functions

```bash
# Install Serverless Framework
npm install -g serverless

# Deploy SMTP Lambda
cd lambdas/smtp/
serverless deploy --stage production

# Deploy API Lambda
cd ../api/
serverless deploy --stage production
```

### 3. Configure EventBridge Rules

```bash
# Create EventBridge rules for email processing
aws events put-rule --name pat-email-received \
  --event-pattern '{"source":["pat.smtp"],"detail-type":["Email Received"]}'

# Add Lambda target
aws events put-targets --rule pat-email-received \
  --targets "Id"="1","Arn"="arn:aws:lambda:region:account:function:pat-email-processor"
```

## Database Migration

### 1. Run Migrations

```bash
# Apply database migrations
docker-compose -f docker-compose.production.yml exec pat-api npm run db:migrate

# Or manually with Go migrate tool
migrate -path migrations/ -database "postgresql://pat_user:password@localhost:5432/pat_production?sslmode=disable" up
```

### 2. Create Initial Admin User

```bash
# Connect to API container
docker-compose -f docker-compose.production.yml exec pat-api bash

# Create admin user (using internal API)
curl -X POST http://localhost:8025/internal/users \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "name": "Administrator",
    "password": "secure_password_here",
    "roles": ["super_admin"]
  }'
```

## Monitoring Setup

### 1. Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'pat-api'
    static_configs:
      - targets: ['pat-api:8025']
    metrics_path: /metrics
    
  - job_name: 'pat-smtp'
    static_configs:
      - targets: ['pat-smtp:1025']
    metrics_path: /metrics
    
  - job_name: 'pat-workflows'
    static_configs:
      - targets: ['pat-workflows:8027']
    metrics_path: /metrics
```

### 2. Grafana Dashboards

Import the provided dashboard configurations:

```bash
# Copy dashboard files
cp -r monitoring/grafana/dashboards/* /var/lib/grafana/dashboards/

# Restart Grafana
docker-compose -f docker-compose.production.yml restart grafana
```

### 3. Alerting Rules

```yaml
# monitoring/prometheus/rules/pat-alerts.yml
groups:
  - name: pat.rules
    rules:
      - alert: HighEmailProcessingTime
        expr: histogram_quantile(0.95, pat_email_processing_duration_seconds) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High email processing time"
          description: "95th percentile processing time is above 5 seconds"
      
      - alert: SMTPConnectionFailures
        expr: rate(pat_smtp_errors_total[5m]) > 0.1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High SMTP error rate"
          description: "SMTP error rate is above 10% for 1 minute"
```

## Plugin System Configuration

### 1. Plugin Directory Setup

```bash
# Create plugin directories
mkdir -p /opt/pat/plugins/{installed,marketplace,temp}
chown -R pat:pat /opt/pat/plugins

# Set up plugin security
mkdir -p /opt/pat/plugins/policies
cat > /opt/pat/plugins/policies/default.json << EOF
{
  "memory_limit": "128MB",
  "execution_timeout": 30000,
  "network_access": false,
  "file_access": {
    "read_only": ["/tmp"],
    "write_only": ["/tmp/plugin-output"]
  },
  "allowed_modules": [
    "lodash",
    "moment",
    "validator"
  ]
}
EOF
```

### 2. Install Sample Plugins

```bash
# Install built-in plugins
docker-compose -f docker-compose.production.yml exec pat-plugins npm run plugins:install-builtin

# Verify plugin installation
curl -X GET http://localhost:8026/api/v1/plugins
```

## SSL and Security Configuration

### 1. Nginx Configuration

```nginx
# nginx/conf.d/pat.conf
upstream pat_frontend {
    server pat-frontend:3000;
}

upstream pat_api {
    server pat-api:8025;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# Frontend
server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    location / {
        proxy_pass http://pat_frontend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}

# API
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    location / {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://pat_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # WebSocket support for GraphQL subscriptions
    location /graphql {
        proxy_pass http://pat_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 2. SMTP Port Configuration

```bash
# Configure firewall for SMTP port
sudo ufw allow 1025/tcp

# For AWS, update security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-your-security-group \
  --protocol tcp \
  --port 1025 \
  --cidr 0.0.0.0/0
```

## Testing the Deployment

### 1. Health Checks

```bash
# Check service health
curl -f http://localhost:8025/health
curl -f http://localhost:3000/api/health

# Check SMTP connectivity
telnet localhost 1025
```

### 2. Send Test Email

```bash
# Using telnet
telnet localhost 1025
HELO test.com
MAIL FROM: test@test.com
RCPT TO: user@yourdomain.com
DATA
Subject: Test Email

This is a test email.
.
QUIT

# Using swaks
swaks --to user@yourdomain.com --from test@test.com --server localhost:1025
```

### 3. Verify AI Analysis

```bash
# Check if AI analysis is working
curl -X POST http://localhost:8025/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "query": "query { emails(first: 1) { edges { node { id sentiment { score label } spamScore { score classification } } } } }"
  }'
```

### 4. Test Workflow Engine

```bash
# Create a test workflow
curl -X POST http://localhost:8025/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "query": "mutation { createWorkflow(input: { name: \"Test Workflow\", triggerRules: [{ type: \"email_received\", conditions: [] }], steps: [{ type: \"log\", name: \"Log Email\", config: { message: \"Email received\" } }] }) { id name } }"
  }'
```

## Performance Tuning

### 1. Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_emails_received_at ON emails (received_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_emails_from_address ON emails (from_address);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_emails_status ON emails (status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_emails_tenant_id ON emails (tenant_id);

-- Configure PostgreSQL
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
SELECT pg_reload_conf();
```

### 2. Redis Configuration

```bash
# Configure Redis for optimal performance
echo "maxmemory 512mb" >> /etc/redis/redis.conf
echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf
echo "save 900 1" >> /etc/redis/redis.conf
echo "save 300 10" >> /etc/redis/redis.conf
echo "save 60 10000" >> /etc/redis/redis.conf
```

### 3. Application Tuning

```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=2048"

# Configure Go runtime
export GOGC=100
export GOMAXPROCS=4
```

## Backup and Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup-database.sh

BACKUP_DIR="/opt/pat/backups"
DATE=$(date +"%Y%m%d_%H%M%S")

mkdir -p $BACKUP_DIR

# PostgreSQL backup
docker-compose -f docker-compose.production.yml exec -T postgres \
  pg_dump -U pat_user -d pat_production | \
  gzip > $BACKUP_DIR/postgres_backup_$DATE.sql.gz

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/postgres_backup_$DATE.sql.gz \
  s3://your-backup-bucket/database/

# Clean old backups (keep last 30 days)
find $BACKUP_DIR -name "postgres_backup_*.sql.gz" -mtime +30 -delete
```

### 2. Redis Backup

```bash
# Redis backup
docker-compose -f docker-compose.production.yml exec redis \
  redis-cli --rdb /data/dump.rdb

# Copy backup
docker cp pat-redis:/data/dump.rdb ./backups/redis_backup_$(date +%Y%m%d).rdb
```

### 3. Email Storage Backup

```bash
# Backup email attachments and data
tar -czf backups/email_storage_$(date +%Y%m%d).tar.gz \
  -C /var/lib/docker/volumes/pat_email_storage/_data .
```

## Troubleshooting

### Common Issues

#### 1. SMTP Connection Issues

```bash
# Check if SMTP port is open
netstat -tlnp | grep :1025

# Check SMTP logs
docker-compose logs pat-smtp

# Test SMTP connectivity
telnet localhost 1025
```

#### 2. Database Connection Problems

```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready -U pat_user

# Check connection parameters
docker-compose exec pat-api env | grep POSTGRES

# View database logs
docker-compose logs postgres
```

#### 3. High Memory Usage

```bash
# Check memory usage
docker stats

# Optimize plugin memory limits
echo "MAX_PLUGIN_MEMORY=64" >> .env.production

# Restart services
docker-compose restart pat-plugins
```

### Log Analysis

```bash
# Centralized logging with ELK stack (optional)
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  elasticsearch:7.14.0

# Configure log forwarding in docker-compose
# Add logging driver configuration to each service
```

## Security Checklist

- [ ] SSL certificates configured and valid
- [ ] JWT keys properly generated and secured
- [ ] Database passwords are strong and unique
- [ ] Redis password configured
- [ ] Firewall rules properly configured
- [ ] Plugin system security policies in place
- [ ] Regular security updates scheduled
- [ ] Backup encryption configured
- [ ] Monitoring and alerting set up
- [ ] Rate limiting configured
- [ ] CORS origins properly restricted

## Production Maintenance

### Daily Tasks

```bash
# Check service health
curl -f https://api.yourdomain.com/health

# Monitor disk usage
df -h

# Check logs for errors
docker-compose logs --tail=100 | grep -i error
```

### Weekly Tasks

```bash
# Update Docker images
docker-compose pull
docker-compose up -d

# Clean old Docker data
docker system prune -f

# Review monitoring dashboards
# Check Grafana alerts
```

### Monthly Tasks

```bash
# Security updates
sudo apt update && sudo apt upgrade

# Review backup integrity
# Performance optimization review
# Capacity planning review
```

## Support and Maintenance

For production support:

- Monitor the health endpoints continuously
- Set up alerting for critical metrics
- Regular backup verification
- Performance monitoring and optimization
- Security updates and patches
- Log analysis and troubleshooting

## Scaling Considerations

### Horizontal Scaling

```yaml
# Scale individual services
docker-compose -f docker-compose.production.yml up -d --scale pat-api=3
docker-compose -f docker-compose.production.yml up -d --scale pat-workflows=2
```

### Load Balancer Configuration

```nginx
# Add to nginx.conf
upstream pat_api_cluster {
    least_conn;
    server pat-api-1:8025;
    server pat-api-2:8025;
    server pat-api-3:8025;
}
```

This deployment guide provides a comprehensive production-ready setup for the Pat email testing platform with all advanced features integrated and properly configured.