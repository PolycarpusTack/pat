# AWS MSK (Managed Streaming for Kafka) Configuration

# MSK Cluster
resource "aws_msk_cluster" "pat" {
  cluster_name           = "${local.name_prefix}-kafka"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = var.environment == "prod" ? 3 : 2

  broker_node_group_info {
    instance_type   = var.environment == "prod" ? "kafka.m5.large" : "kafka.t3.small"
    client_subnets  = module.vpc.private_subnets
    security_groups = [aws_security_group.msk.id]
    
    storage_info {
      ebs_storage_info {
        volume_size             = var.environment == "prod" ? 100 : 50
        provisioned_throughput {
          enabled           = var.environment == "prod"
          volume_throughput = var.environment == "prod" ? 250 : null
        }
      }
    }
    
    connectivity_info {
      public_access {
        type = "DISABLED"
      }
    }
  }

  client_authentication {
    sasl {
      iam   = true
      scram = false
    }
    tls {
      certificate_authority_arns = []
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.pat.arn
    
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.pat.arn
    revision = aws_msk_configuration.pat.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
      s3 {
        enabled = false
      }
    }
  }

  open_monitoring {
    prometheus {
      jmx_exporter {
        enabled_in_broker = true
      }
      node_exporter {
        enabled_in_broker = true
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kafka"
  })
}

# MSK Configuration
resource "aws_msk_configuration" "pat" {
  name = "${local.name_prefix}-kafka-config"

  kafka_versions = ["3.5.1"]

  server_properties = <<PROPERTIES
auto.create.topics.enable = true
default.replication.factor = ${var.environment == "prod" ? 3 : 2}
min.insync.replicas = ${var.environment == "prod" ? 2 : 1}
unclean.leader.election.enable = false
log.retention.hours = 168
log.segment.bytes = 1073741824
compression.type = lz4
num.partitions = ${var.environment == "prod" ? 6 : 3}
transaction.state.log.replication.factor = ${var.environment == "prod" ? 3 : 2}
transaction.state.log.min.isr = ${var.environment == "prod" ? 2 : 1}
PROPERTIES

  description = "Configuration for Pat Kafka cluster"
}

# Security Group for MSK
resource "aws_security_group" "msk" {
  name_prefix = "${local.name_prefix}-msk-"
  description = "Security group for Pat MSK cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Kafka plaintext from Lambda"
  }

  ingress {
    from_port       = 9094
    to_port         = 9094
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Kafka TLS from Lambda"
  }

  ingress {
    from_port       = 9096
    to_port         = 9096
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Kafka SASL/SCRAM from Lambda"
  }

  ingress {
    from_port       = 2181
    to_port         = 2181
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Zookeeper from Lambda"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-msk-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# CloudWatch Log Group for MSK
resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# MSK Scram Secret (if using SCRAM authentication)
resource "aws_secretsmanager_secret" "msk_scram" {
  count                   = var.msk_auth_scram_enabled ? 1 : 0
  name                    = "${local.name_prefix}-msk-scram"
  description             = "SCRAM credentials for MSK"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-msk-scram"
  })
}

# IAM Policy for MSK Access
resource "aws_iam_policy" "msk_access" {
  name        = "${local.name_prefix}-msk-access"
  description = "Policy for accessing Pat MSK cluster"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:Connect",
          "kafka-cluster:AlterCluster",
          "kafka-cluster:DescribeCluster"
        ]
        Resource = aws_msk_cluster.pat.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:*Topic*",
          "kafka-cluster:WriteData",
          "kafka-cluster:ReadData"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:topic/${aws_msk_cluster.pat.cluster_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:AlterGroup",
          "kafka-cluster:DescribeGroup"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:group/${aws_msk_cluster.pat.cluster_name}/*"
      }
    ]
  })
}

# Attach MSK policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_msk" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = aws_iam_policy.msk_access.arn
}

# MSK Auto Scaling
resource "aws_appautoscaling_target" "msk_storage" {
  count              = var.msk_autoscaling_enabled ? 1 : 0
  max_capacity       = var.environment == "prod" ? 1000 : 100
  min_capacity       = var.environment == "prod" ? 100 : 50
  resource_id        = aws_msk_cluster.pat.arn
  scalable_dimension = "kafka:broker-storage:VolumeSize"
  service_namespace  = "kafka"
}

resource "aws_appautoscaling_policy" "msk_storage_policy" {
  count              = var.msk_autoscaling_enabled ? 1 : 0
  name               = "${local.name_prefix}-msk-storage-policy"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.msk_storage[0].resource_id
  scalable_dimension = aws_appautoscaling_target.msk_storage[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.msk_storage[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "KafkaBrokerStorageUtilization"
    }
    target_value = 70.0
  }
}

# MSK Connect Connector for S3 Sink (optional)
resource "aws_mskconnect_connector" "s3_sink" {
  count = var.msk_connect_enabled ? 1 : 0
  
  name = "${local.name_prefix}-s3-sink"

  kafkaconnect_version = "2.7.1"

  capacity {
    autoscaling {
      mcu_count        = 1
      min_worker_count = 1
      max_worker_count = 2

      scale_in_policy {
        cpu_utilization_percentage = 20
      }

      scale_out_policy {
        cpu_utilization_percentage = 80
      }
    }
  }

  connector_configuration = {
    "connector.class"                = "io.confluent.connect.s3.S3SinkConnector"
    "s3.region"                      = var.aws_region
    "s3.bucket.name"                 = aws_s3_bucket.kafka_sink[0].id
    "topics"                         = "pat-emails,pat-events"
    "tasks.max"                      = "2"
    "format.class"                   = "io.confluent.connect.s3.format.json.JsonFormat"
    "flush.size"                     = "1000"
    "rotate.interval.ms"             = "60000"
    "storage.class"                  = "io.confluent.connect.storage.tools.ByteArrayFormat"
    "topics.dir"                     = "topics"
    "partitioner.class"              = "io.confluent.connect.storage.partitioner.DefaultPartitioner"
    "schema.compatibility"           = "NONE"
  }

  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = aws_msk_cluster.pat.bootstrap_brokers_tls
      vpc {
        security_groups = [aws_security_group.msk.id]
        subnets         = module.vpc.private_subnets
      }
    }
  }

  kafka_cluster_client_authentication {
    authentication_type = "IAM"
  }

  kafka_cluster_encryption_in_transit {
    encryption_type = "TLS"
  }

  plugin {
    custom_plugin {
      arn      = aws_mskconnect_custom_plugin.s3_sink[0].arn
      revision = aws_mskconnect_custom_plugin.s3_sink[0].latest_revision
    }
  }

  service_execution_role_arn = aws_iam_role.msk_connect[0].arn

  log_delivery {
    worker_log_delivery {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk_connect[0].name
      }
    }
  }
}