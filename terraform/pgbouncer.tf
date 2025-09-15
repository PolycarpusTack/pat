# PgBouncer deployment for connection pooling

# Security group for PgBouncer
resource "aws_security_group" "pgbouncer" {
  name_prefix = "${local.name_prefix}-pgbouncer-"
  description = "Security group for PgBouncer"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "PostgreSQL from Lambda"
  }

  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
    description     = "PostgreSQL to RDS"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AWS API"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-pgbouncer-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ECS Task Definition for PgBouncer
resource "aws_ecs_task_definition" "pgbouncer" {
  family                   = "${local.name_prefix}-pgbouncer"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.environment == "prod" ? "1024" : "512"
  memory                   = var.environment == "prod" ? "2048" : "1024"
  execution_role_arn       = aws_iam_role.pgbouncer_execution.arn
  task_role_arn            = aws_iam_role.pgbouncer_task.arn

  container_definitions = jsonencode([
    {
      name  = "pgbouncer"
      image = "pgbouncer/pgbouncer:latest"
      
      portMappings = [
        {
          containerPort = 5432
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "DATABASES_HOST"
          value = aws_rds_cluster.pat.endpoint
        },
        {
          name  = "DATABASES_PORT"
          value = "5432"
        },
        {
          name  = "DATABASES_DATABASE"
          value = aws_rds_cluster.pat.database_name
        },
        {
          name  = "POOL_MODE"
          value = "transaction"
        },
        {
          name  = "MAX_CLIENT_CONN"
          value = var.environment == "prod" ? "1000" : "100"
        },
        {
          name  = "DEFAULT_POOL_SIZE"
          value = var.environment == "prod" ? "25" : "10"
        },
        {
          name  = "MIN_POOL_SIZE"
          value = "5"
        },
        {
          name  = "RESERVE_POOL_SIZE"
          value = "5"
        },
        {
          name  = "RESERVE_POOL_TIMEOUT"
          value = "3"
        },
        {
          name  = "SERVER_LIFETIME"
          value = "3600"
        },
        {
          name  = "SERVER_IDLE_TIMEOUT"
          value = "600"
        }
      ]

      secrets = [
        {
          name      = "DATABASES_USER"
          valueFrom = "${aws_secretsmanager_secret.db_password.arn}:username::"
        },
        {
          name      = "DATABASES_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.db_password.arn}:password::"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.pgbouncer.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "pgbouncer"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "pg_isready -h localhost -p 5432"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
    }
  ])

  tags = local.common_tags
}

# ECS Service for PgBouncer
resource "aws_ecs_service" "pgbouncer" {
  name            = "${local.name_prefix}-pgbouncer"
  cluster         = aws_ecs_cluster.pat.id
  task_definition = aws_ecs_task_definition.pgbouncer.arn
  desired_count   = var.environment == "prod" ? 3 : 1

  launch_type = "FARGATE"

  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [aws_security_group.pgbouncer.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.pgbouncer.arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
  }

  tags = local.common_tags
}

# Service Discovery for PgBouncer
resource "aws_service_discovery_service" "pgbouncer" {
  name = "pgbouncer"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.pat.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 2
  }

  tags = local.common_tags
}

# CloudWatch Log Group for PgBouncer
resource "aws_cloudwatch_log_group" "pgbouncer" {
  name              = "/ecs/${local.name_prefix}/pgbouncer"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# IAM Role for PgBouncer Task Execution
resource "aws_iam_role" "pgbouncer_execution" {
  name = "${local.name_prefix}-pgbouncer-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "pgbouncer_execution" {
  role       = aws_iam_role.pgbouncer_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "pgbouncer_secrets" {
  name = "pgbouncer-secrets"
  role = aws_iam_role.pgbouncer_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_password.arn
        ]
      }
    ]
  })
}

# IAM Role for PgBouncer Task
resource "aws_iam_role" "pgbouncer_task" {
  name = "${local.name_prefix}-pgbouncer-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Outputs
output "pgbouncer_endpoint" {
  value = "pgbouncer.${aws_service_discovery_private_dns_namespace.pat.name}:5432"
}