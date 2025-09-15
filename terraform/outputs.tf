# Outputs for Pat Infrastructure

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = module.vpc.public_subnets
}

# Security Group Outputs
output "lambda_security_group_id" {
  description = "Security group ID for Lambda functions"
  value       = aws_security_group.lambda.id
}

output "api_gateway_security_group_id" {
  description = "Security group ID for API Gateway"
  value       = aws_security_group.api_gateway.id
}

# S3 Bucket Outputs
output "attachments_bucket_name" {
  description = "Name of the attachments S3 bucket"
  value       = aws_s3_bucket.attachments.id
}

output "attachments_bucket_arn" {
  description = "ARN of the attachments S3 bucket"
  value       = aws_s3_bucket.attachments.arn
}

output "lambda_deployments_bucket_name" {
  description = "Name of the Lambda deployments S3 bucket"
  value       = aws_s3_bucket.lambda_deployments.id
}

# CloudFront Outputs
output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.attachments.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.attachments.domain_name
}

# KMS Outputs
output "kms_key_id" {
  description = "ID of the KMS key"
  value       = aws_kms_key.pat.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key"
  value       = aws_kms_key.pat.arn
}

# IAM Role Outputs
output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution.arn
}

output "api_gateway_role_arn" {
  description = "ARN of the API Gateway role"
  value       = aws_iam_role.api_gateway.arn
}

# SQS Queue Outputs
output "email_processing_queue_url" {
  description = "URL of the email processing SQS queue"
  value       = aws_sqs_queue.email_processing.id
}

output "email_processing_queue_arn" {
  description = "ARN of the email processing SQS queue"
  value       = aws_sqs_queue.email_processing.arn
}

output "notifications_queue_url" {
  description = "URL of the notifications SQS queue"
  value       = aws_sqs_queue.notifications.id
}

output "plugin_execution_queue_url" {
  description = "URL of the plugin execution SQS queue"
  value       = aws_sqs_queue.plugin_execution.id
}

# Secrets Manager Outputs
output "app_secrets_arn" {
  description = "ARN of the application secrets"
  value       = aws_secretsmanager_secret.app_secrets.arn
  sensitive   = true
}

output "db_credentials_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.db_credentials.arn
  sensitive   = true
}

# Environment Configuration
output "environment_config" {
  description = "Environment configuration for applications"
  value = {
    environment = var.environment
    region      = var.aws_region
    vpc_id      = module.vpc.vpc_id
    kms_key_id  = aws_kms_key.pat.id
  }
}

# Connection Information
output "connection_info" {
  description = "Connection information for Pat services"
  value = {
    attachments_cdn_url = "https://${aws_cloudfront_distribution.attachments.domain_name}"
    region              = var.aws_region
  }
}