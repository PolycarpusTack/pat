# Lambda Function for SMTP Processing

# Lambda Function
resource "aws_lambda_function" "smtp_handler" {
  filename         = data.archive_file.smtp_handler.output_path
  function_name    = "${local.name_prefix}-smtp-handler"
  role            = aws_iam_role.smtp_lambda_execution.arn
  handler         = "main"
  runtime         = "provided.al2"
  architectures   = ["x86_64"]
  timeout         = 900 # 15 minutes for long SMTP sessions
  memory_size     = var.environment == "prod" ? 3008 : 1024
  
  environment {
    variables = {
      ENVIRONMENT      = var.environment
      S3_BUCKET        = aws_s3_bucket.attachments.id
      SQS_QUEUE_URL    = aws_sqs_queue.email_processing.id
      KAFKA_BROKERS    = aws_msk_cluster.pat.bootstrap_brokers_tls
      KAFKA_TOPIC      = "pat-events"
      SMTP_HOSTNAME    = var.domain_name
      SMTP_REQUIRE_TLS = var.environment == "prod" ? "true" : "false"
      SMTP_REQUIRE_AUTH = "false"
      TENANT_ID        = var.default_tenant_id
    }
  }

  vpc_config {
    subnet_ids         = module.vpc.private_subnets
    security_group_ids = [aws_security_group.lambda.id]
  }

  tracing_config {
    mode = "Active"
  }

  reserved_concurrent_executions = var.environment == "prod" ? 1000 : 100

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-handler"
  })
}

# Lambda Layer for shared dependencies
resource "aws_lambda_layer_version" "smtp_deps" {
  filename            = data.archive_file.smtp_deps.output_path
  layer_name          = "${local.name_prefix}-smtp-deps"
  compatible_runtimes = ["provided.al2"]
  description         = "Shared dependencies for SMTP handler"

  lifecycle {
    create_before_destroy = true
  }
}

# Archive for Lambda deployment
data "archive_file" "smtp_handler" {
  type        = "zip"
  output_path = "${path.module}/.terraform/tmp/smtp-handler.zip"
  
  source {
    content  = file("${path.module}/../cmd/lambda/smtp/main")
    filename = "main"
  }
}

data "archive_file" "smtp_deps" {
  type        = "zip"
  output_path = "${path.module}/.terraform/tmp/smtp-deps.zip"
  source_dir  = "${path.module}/../build/lambda-layers/smtp"
}

# IAM Role for Lambda
resource "aws_iam_role" "smtp_lambda_execution" {
  name = "${local.name_prefix}-smtp-lambda-execution"

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

# Attach AWS managed policy for VPC access
resource "aws_iam_role_policy_attachment" "smtp_lambda_vpc" {
  role       = aws_iam_role.smtp_lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Attach AWS managed policy for X-Ray
resource "aws_iam_role_policy_attachment" "smtp_lambda_xray" {
  role       = aws_iam_role.smtp_lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Custom policy for Lambda
resource "aws_iam_role_policy" "smtp_lambda_policy" {
  name = "${local.name_prefix}-smtp-lambda-policy"
  role = aws_iam_role.smtp_lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.attachments.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.email_processing.arn
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
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_password.arn,
          aws_secretsmanager_secret.redis_auth_token.arn
        ]
      }
    ]
  })
}

# Lambda Insights Layer
resource "aws_lambda_function_event_invoke_config" "smtp_handler" {
  function_name                = aws_lambda_function.smtp_handler.function_name
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 0 # No retries for SMTP

  on_failure {
    destination = aws_sqs_queue.email_processing_dlq.arn
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "smtp_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.smtp_handler.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# CloudWatch Metrics and Alarms
resource "aws_cloudwatch_metric_alarm" "smtp_lambda_errors" {
  alarm_name          = "${local.name_prefix}-smtp-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "SMTP Lambda function errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.smtp_handler.function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "smtp_lambda_throttles" {
  alarm_name          = "${local.name_prefix}-smtp-lambda-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "SMTP Lambda function throttles"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.smtp_handler.function_name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "smtp_lambda_duration" {
  alarm_name          = "${local.name_prefix}-smtp-lambda-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "30000" # 30 seconds
  alarm_description   = "SMTP Lambda function high duration"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.smtp_handler.function_name
  }

  tags = local.common_tags
}

# Auto-scaling for Lambda concurrency
resource "aws_lambda_provisioned_concurrency_config" "smtp_handler" {
  count = var.environment == "prod" ? 1 : 0

  function_name                     = aws_lambda_function.smtp_handler.function_name
  provisioned_concurrent_executions = 10
  qualifier                         = aws_lambda_function.smtp_handler.version

  lifecycle {
    ignore_changes = [provisioned_concurrent_executions]
  }
}

# Application Auto Scaling target
resource "aws_appautoscaling_target" "smtp_lambda" {
  count = var.environment == "prod" ? 1 : 0

  max_capacity       = 100
  min_capacity       = 10
  resource_id        = "function:${aws_lambda_function.smtp_handler.function_name}:provisioned-concurrency:${aws_lambda_function.smtp_handler.version}"
  scalable_dimension = "lambda:function:ProvisionedConcurrency"
  service_namespace  = "lambda"
}

# Auto Scaling policy
resource "aws_appautoscaling_policy" "smtp_lambda" {
  count = var.environment == "prod" ? 1 : 0

  name               = "${local.name_prefix}-smtp-lambda-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.smtp_lambda[0].resource_id
  scalable_dimension = aws_appautoscaling_target.smtp_lambda[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.smtp_lambda[0].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 0.7

    predefined_metric_specification {
      predefined_metric_type = "LambdaProvisionedConcurrencyUtilization"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}