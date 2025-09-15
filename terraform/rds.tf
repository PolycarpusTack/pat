# AWS RDS Aurora PostgreSQL Configuration for Pat

# DB Subnet Group
resource "aws_db_subnet_group" "pat" {
  name       = "${local.name_prefix}-db"
  subnet_ids = module.vpc.database_subnets

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
  })
}

# RDS Cluster Parameter Group
resource "aws_rds_cluster_parameter_group" "pat" {
  family      = "aurora-postgresql15"
  name_prefix = "${local.name_prefix}-cluster-"
  description = "Parameter group for Pat Aurora PostgreSQL cluster"

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,pglogical,pg_cron"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "100" # Log queries taking more than 100ms
  }

  parameter {
    name  = "max_connections"
    value = var.environment == "prod" ? "1000" : "200"
  }

  parameter {
    name  = "effective_cache_size"
    value = "{DBInstanceClassMemory*3/4}"
  }

  parameter {
    name  = "work_mem"
    value = "16384" # 16MB
  }

  parameter {
    name  = "maintenance_work_mem"
    value = "524288" # 512MB
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# DB Instance Parameter Group
resource "aws_db_parameter_group" "pat" {
  family      = "aurora-postgresql15"
  name_prefix = "${local.name_prefix}-instance-"
  description = "Parameter group for Pat Aurora PostgreSQL instances"

  parameter {
    name  = "max_connections"
    value = var.environment == "prod" ? "1000" : "200"
  }

  parameter {
    name  = "shared_buffers"
    value = "{DBInstanceClassMemory*3/4}"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# RDS Aurora Cluster
resource "aws_rds_cluster" "pat" {
  cluster_identifier = "${local.name_prefix}-cluster"
  engine             = "aurora-postgresql"
  engine_version     = "15.4"
  engine_mode        = "provisioned"

  database_name   = "pat"
  master_username = "patadmin"
  master_password = random_password.db_password.result

  db_subnet_group_name            = aws_db_subnet_group.pat.name
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.pat.name

  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period         = var.environment == "prod" ? 30 : 7
  preferred_backup_window         = "03:00-04:00"
  preferred_maintenance_window    = "sun:04:00-sun:05:00"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  storage_encrypted = true
  kms_key_id        = aws_kms_key.pat.arn

  deletion_protection = var.environment == "prod"
  skip_final_snapshot = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${local.name_prefix}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  enable_global_write_forwarding = true
  enable_http_endpoint           = true

  serverlessv2_scaling_configuration {
    max_capacity = var.environment == "prod" ? 64 : 4
    min_capacity = var.environment == "prod" ? 2 : 0.5
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-aurora-cluster"
  })
}

# Primary Instance
resource "aws_rds_cluster_instance" "primary" {
  identifier                   = "${local.name_prefix}-primary"
  cluster_identifier           = aws_rds_cluster.pat.id
  instance_class               = "db.serverless"
  engine                       = aws_rds_cluster.pat.engine
  engine_version               = aws_rds_cluster.pat.engine_version
  db_parameter_group_name      = aws_db_parameter_group.pat.name
  
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.pat.arn
  performance_insights_retention_period = var.environment == "prod" ? 731 : 7

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-aurora-primary"
  })
}

# Read Replicas
resource "aws_rds_cluster_instance" "replicas" {
  count = var.environment == "prod" ? 2 : 1

  identifier                   = "${local.name_prefix}-replica-${count.index + 1}"
  cluster_identifier           = aws_rds_cluster.pat.id
  instance_class               = "db.serverless"
  engine                       = aws_rds_cluster.pat.engine
  engine_version               = aws_rds_cluster.pat.engine_version
  db_parameter_group_name      = aws_db_parameter_group.pat.name
  
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.pat.arn
  performance_insights_retention_period = var.environment == "prod" ? 731 : 7

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-aurora-replica-${count.index + 1}"
  })
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name_prefix = "${local.name_prefix}-rds-"
  description = "Security group for Pat RDS cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "PostgreSQL from Lambda"
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.pgbouncer.id]
    description     = "PostgreSQL from PgBouncer"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Random password for RDS
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Store password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name_prefix             = "${local.name_prefix}-db-password-"
  description             = "Master password for Pat RDS cluster"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-password"
  })
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = aws_rds_cluster.pat.master_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_rds_cluster.pat.endpoint
    port     = 5432
    dbname   = aws_rds_cluster.pat.database_name
  })
}

# IAM Role for RDS Monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name_prefix}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${local.name_prefix}-rds-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.pat.cluster_identifier
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  alarm_name          = "${local.name_prefix}-rds-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = var.environment == "prod" ? "800" : "150"
  alarm_description   = "RDS connection count"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.pat.cluster_identifier
  }

  tags = local.common_tags
}

# Outputs
output "rds_cluster" {
  value = {
    endpoint        = aws_rds_cluster.pat.endpoint
    reader_endpoint = aws_rds_cluster.pat.reader_endpoint
    database_name   = aws_rds_cluster.pat.database_name
    port            = aws_rds_cluster.pat.port
    secret_arn      = aws_secretsmanager_secret.db_password.arn
  }
  sensitive = true
}