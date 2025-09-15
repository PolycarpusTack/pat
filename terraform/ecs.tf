# ECS Cluster for Pat services

# ECS Cluster
resource "aws_ecs_cluster" "pat" {
  name = local.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.pat.id
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ecs-cluster"
  })
}

# ECS Cluster Capacity Providers
resource "aws_ecs_cluster_capacity_providers" "pat" {
  cluster_name = aws_ecs_cluster.pat.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }

  default_capacity_provider_strategy {
    weight            = var.environment == "prod" ? 0 : 50
    capacity_provider = "FARGATE_SPOT"
  }
}

# Service Discovery Namespace
resource "aws_service_discovery_private_dns_namespace" "pat" {
  name        = "${local.name_prefix}.local"
  description = "Private DNS namespace for Pat services"
  vpc         = module.vpc.vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-service-discovery"
  })
}

# CloudWatch Log Group for ECS Exec
resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/${local.name_prefix}/exec"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}