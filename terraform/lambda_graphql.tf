# Lambda Function for GraphQL API

# Lambda Function
resource "aws_lambda_function" "graphql" {
  filename         = data.archive_file.graphql.output_path
  function_name    = "${local.name_prefix}-graphql"
  role            = aws_iam_role.graphql_lambda_execution.arn
  handler         = "index.handler"
  runtime         = "nodejs18.x"
  architectures   = ["x86_64"]
  timeout         = 30
  memory_size     = var.environment == "prod" ? 1024 : 512
  
  environment {
    variables = {
      NODE_ENV         = var.environment
      DATABASE_URL     = "postgresql://${aws_rds_cluster.pat.master_username}:${random_password.db_password.result}@${aws_rds_cluster.pat.endpoint}:${aws_rds_cluster.pat.port}/${aws_rds_cluster.pat.database_name}"
      REDIS_URL        = "rediss://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.pat.configuration_endpoint_address}:6379"
      JWT_SECRET       = random_password.jwt_secret.result
      S3_BUCKET        = aws_s3_bucket.attachments.id
      KAFKA_BROKERS    = aws_msk_cluster.pat.bootstrap_brokers_tls
      CORS_ORIGIN      = var.cors_origin
      METRICS_ENABLED  = var.environment == "prod" ? "true" : "false"
    }
  }

  vpc_config {
    subnet_ids         = module.vpc.private_subnets
    security_group_ids = [aws_security_group.lambda.id]
  }

  tracing_config {
    mode = "Active"
  }

  layers = [
    aws_lambda_layer_version.graphql_deps.arn,
    "arn:aws:lambda:${var.aws_region}:580247275435:layer:LambdaInsightsExtension:21",
  ]

  reserved_concurrent_executions = var.environment == "prod" ? 100 : 10

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-graphql-lambda"
  })
}

# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "graphql_deps" {
  filename            = data.archive_file.graphql_deps.output_path
  layer_name          = "${local.name_prefix}-graphql-deps"
  compatible_runtimes = ["nodejs18.x"]
  description         = "GraphQL API dependencies"

  lifecycle {
    create_before_destroy = true
  }
}

# Archive for Lambda deployment
data "archive_file" "graphql" {
  type        = "zip"
  output_path = "${path.module}/.terraform/tmp/graphql.zip"
  source_dir  = "${path.module}/../api/graphql/dist"
}

data "archive_file" "graphql_deps" {
  type        = "zip"
  output_path = "${path.module}/.terraform/tmp/graphql-deps.zip"
  source_dir  = "${path.module}/../api/graphql/node_modules"
}

# IAM Role for Lambda
resource "aws_iam_role" "graphql_lambda_execution" {
  name = "${local.name_prefix}-graphql-lambda-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach AWS managed policies
resource "aws_iam_role_policy_attachment" "graphql_lambda_vpc" {
  role       = aws_iam_role.graphql_lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "graphql_lambda_xray" {
  role       = aws_iam_role.graphql_lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy_attachment" "graphql_lambda_insights" {
  role       = aws_iam_role.graphql_lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLambdaInsightsExecutionRolePolicy"
}

# Custom policy for Lambda
resource "aws_iam_role_policy" "graphql_lambda_policy" {
  name = "${local.name_prefix}-graphql-lambda-policy"
  role = aws_iam_role.graphql_lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.attachments.arn,
          "${aws_s3_bucket.attachments.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.email_processing.arn,
          aws_sqs_queue.plugin_execution.arn,
          aws_sqs_queue.workflow_execution.arn,
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_password.arn,
          aws_secretsmanager_secret.redis_auth_token.arn,
          aws_secretsmanager_secret.jwt_secret.arn,
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.pat.arn
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = aws_cloudwatch_event_bus.pat.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:Connect",
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
      }
    ]
  })
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "graphql_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.graphql.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# Random password for JWT secret
resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

# Store JWT secret in Secrets Manager
resource "aws_secretsmanager_secret" "jwt_secret" {
  name_prefix             = "${local.name_prefix}-jwt-secret-"
  description             = "JWT secret for Pat GraphQL API"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-jwt-secret"
  })
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = random_password.jwt_secret.result
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "graphql_lambda_errors" {
  alarm_name          = "${local.name_prefix}-graphql-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "GraphQL Lambda function errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.graphql.function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "graphql_lambda_duration" {
  alarm_name          = "${local.name_prefix}-graphql-lambda-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "3000" # 3 seconds
  alarm_description   = "GraphQL Lambda function duration"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.graphql.function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "graphql_lambda_concurrent" {
  alarm_name          = "${local.name_prefix}-graphql-lambda-concurrent"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ConcurrentExecutions"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Maximum"
  threshold           = var.environment == "prod" ? "80" : "8"
  alarm_description   = "GraphQL Lambda concurrent executions"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.graphql.function_name
  }

  tags = local.common_tags
}