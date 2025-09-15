# AWS ElastiCache Redis Configuration for Pat

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "pat" {
  name       = "${local.name_prefix}-redis"
  subnet_ids = module.vpc.elasticache_subnets

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-subnet-group"
  })
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "pat" {
  family      = "redis7"
  name_prefix = "${local.name_prefix}-redis-"
  description = "Parameter group for Pat Redis cluster"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  parameter {
    name  = "timeout"
    value = "300"
  }

  parameter {
    name  = "tcp-keepalive"
    value = "60"
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# ElastiCache Replication Group (Redis Cluster)
resource "aws_elasticache_replication_group" "pat" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "Redis cluster for Pat platform"

  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.environment == "prod" ? "cache.r7g.xlarge" : "cache.t3.small"
  parameter_group_name = aws_elasticache_parameter_group.pat.name

  # Cluster mode
  num_node_groups         = var.environment == "prod" ? 3 : 1
  replicas_per_node_group = var.environment == "prod" ? 2 : 1

  subnet_group_name          = aws_elasticache_subnet_group.pat.name
  security_group_ids         = [aws_security_group.redis.id]

  # Persistence
  snapshot_retention_limit = var.environment == "prod" ? 7 : 1
  snapshot_window          = "03:00-05:00"
  maintenance_window       = "sun:05:00-sun:06:00"

  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled         = true
  auth_token                 = random_password.redis_auth_token.result

  # High availability
  automatic_failover_enabled = true
  multi_az_enabled           = true

  # Backup
  final_snapshot_identifier = var.environment == "prod" ? "${local.name_prefix}-redis-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Notifications
  notification_topic_arn = aws_sns_topic.alerts.arn

  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_engine.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-cluster"
  })
}

# Security Group for Redis
resource "aws_security_group" "redis" {
  name_prefix = "${local.name_prefix}-redis-"
  description = "Security group for Pat Redis cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Redis from Lambda"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Random auth token for Redis
resource "random_password" "redis_auth_token" {
  length  = 64
  special = false # Redis AUTH tokens don't support special characters
}

# Store auth token in Secrets Manager
resource "aws_secretsmanager_secret" "redis_auth_token" {
  name_prefix             = "${local.name_prefix}-redis-auth-"
  description             = "Auth token for Pat Redis cluster"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-redis-auth"
  })
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  secret_id = aws_secretsmanager_secret.redis_auth_token.id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth_token.result
    endpoint   = aws_elasticache_replication_group.pat.configuration_endpoint_address
    port       = 6379
  })
}

# CloudWatch Log Groups for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/aws/elasticache/${local.name_prefix}/redis/slow-log"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "redis_engine" {
  name              = "/aws/elasticache/${local.name_prefix}/redis/engine-log"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "${local.name_prefix}-redis-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "75"
  alarm_description   = "Redis CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.pat.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${local.name_prefix}-redis-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Redis memory usage"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.pat.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  alarm_name          = "${local.name_prefix}-redis-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "Redis evictions rate"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    CacheClusterId = aws_elasticache_replication_group.pat.id
  }

  tags = local.common_tags
}

# Outputs
output "redis_cluster" {
  value = {
    configuration_endpoint = aws_elasticache_replication_group.pat.configuration_endpoint_address
    cluster_enabled        = aws_elasticache_replication_group.pat.cluster_enabled
    auth_token_secret_arn  = aws_secretsmanager_secret.redis_auth_token.arn
  }
  sensitive = true
}