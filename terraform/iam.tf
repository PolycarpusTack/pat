# IAM Roles and Policies for Pat

# Lambda Execution Role
resource "aws_iam_role" "lambda_execution" {
  name = "${local.name_prefix}-lambda-execution"
  
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

# Lambda Basic Execution Policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda VPC Access Policy
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Custom Lambda Policy
resource "aws_iam_role_policy" "lambda_custom" {
  name = "${local.name_prefix}-lambda-custom"
  role = aws_iam_role.lambda_execution.id
  
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
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.app_secrets.arn
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
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.email_processing.arn
      }
    ]
  })
}

# API Gateway Execution Role
resource "aws_iam_role" "api_gateway" {
  name = "${local.name_prefix}-api-gateway"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# API Gateway CloudWatch Logs Policy
resource "aws_iam_role_policy_attachment" "api_gateway_logs" {
  role       = aws_iam_role.api_gateway.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

# EventBridge Role for Lambda Invocation
resource "aws_iam_role" "eventbridge" {
  name = "${local.name_prefix}-eventbridge"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# EventBridge Lambda Invocation Policy
resource "aws_iam_role_policy" "eventbridge_lambda" {
  name = "${local.name_prefix}-eventbridge-lambda"
  role = aws_iam_role.eventbridge.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-*"
      }
    ]
  })
}

# S3 Bucket Policy for CloudFront
data "aws_iam_policy_document" "s3_bucket_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.attachments.arn}/*"]
    
    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.attachments.iam_arn]
    }
  }
}

# KMS Key Policy
data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    
    actions   = ["kms:*"]
    resources = ["*"]
  }
  
  statement {
    sid    = "Allow Lambda to use the key"
    effect = "Allow"
    
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_execution.arn]
    }
    
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]
    
    resources = ["*"]
  }
}