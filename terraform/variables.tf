# Input Variables for Pat Infrastructure

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "owner_email" {
  description = "Email of the infrastructure owner"
  type        = string
}

# VPC Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets"
  type        = bool
  default     = false
}

# Lambda Configuration
variable "lambda_memory_size" {
  description = "Memory size for Lambda functions"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Timeout for Lambda functions in seconds"
  type        = number
  default     = 30
}

variable "lambda_reserved_concurrent_executions" {
  description = "Reserved concurrent executions for Lambda"
  type        = number
  default     = 100
}

# API Gateway Configuration
variable "api_gateway_stage_name" {
  description = "API Gateway stage name"
  type        = string
  default     = "v1"
}

variable "api_gateway_throttle_rate_limit" {
  description = "API Gateway throttle rate limit"
  type        = number
  default     = 10000
}

variable "api_gateway_throttle_burst_limit" {
  description = "API Gateway throttle burst limit"
  type        = number
  default     = 5000
}

# S3 Configuration
variable "s3_versioning_enabled" {
  description = "Enable versioning for S3 buckets"
  type        = bool
  default     = true
}

variable "s3_lifecycle_days" {
  description = "Days before moving objects to cheaper storage"
  type        = number
  default     = 30
}

# Secrets Manager
variable "enable_secret_rotation" {
  description = "Enable automatic secret rotation"
  type        = bool
  default     = true
}

variable "secret_rotation_days" {
  description = "Days between secret rotations"
  type        = number
  default     = 30
}

# Monitoring
variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

# Security
variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the infrastructure"
  type        = list(string)
  default     = []
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Use spot instances where applicable"
  type        = bool
  default     = false
}

# Tags
variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}