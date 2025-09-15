# =============================================================================
# Pat Fortress - Terraform Infrastructure as Code
# Multi-Cloud Production Deployment with EKS
# =============================================================================

terraform {
  required_version = ">= 1.5"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }

  backend "s3" {
    bucket         = var.terraform_state_bucket
    key            = "fortress/terraform.tfstate"
    region         = var.aws_region
    encrypt        = true
    dynamodb_table = "fortress-terraform-locks"
  }
}

# =============================================================================
# Provider Configuration
# =============================================================================
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Pat-Fortress"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner_email
      Application = "email-testing-platform"
      CostCenter  = "platform"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# =============================================================================
# Local Variables
# =============================================================================
locals {
  project_name = "pat-fortress"
  environment  = var.environment
  
  common_tags = {
    Project     = local.project_name
    Environment = local.environment
    ManagedBy   = "terraform"
    Owner       = "fortress-team"
    CostCenter  = "platform"
    Application = "email-testing"
  }

  # Kubernetes cluster configuration
  cluster_name    = "${local.project_name}-${local.environment}"
  cluster_version = var.kubernetes_version

  # Network configuration
  vpc_cidr             = var.vpc_cidr
  availability_zones   = data.aws_availability_zones.available.names
  private_subnets      = [for k, v in local.availability_zones : cidrsubnet(local.vpc_cidr, 8, k)]
  public_subnets       = [for k, v in local.availability_zones : cidrsubnet(local.vpc_cidr, 8, k + 100)]
  database_subnets     = [for k, v in local.availability_zones : cidrsubnet(local.vpc_cidr, 8, k + 200)]

  # Domain configuration
  domain_name = var.domain_name
  subdomain   = "${local.environment}.${local.domain_name}"
}

# =============================================================================
# Data Sources
# =============================================================================
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Random suffix for globally unique names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}