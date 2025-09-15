# Additional Provider Configuration

# Provider for replica region (production only)
provider "aws" {
  alias  = "replica"
  region = var.environment == "prod" ? "us-west-2" : var.aws_region
  
  default_tags {
    tags = {
      Project     = "Pat"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner_email
      Region      = "replica"
    }
  }
}

# Provider for Route53 (always in us-east-1)
provider "aws" {
  alias  = "route53"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Project     = "Pat"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner_email
      Service     = "route53"
    }
  }
}

# Terraform version constraints
terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}