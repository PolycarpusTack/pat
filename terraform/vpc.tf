# VPC Configuration for Pat

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr
  
  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 10)]
  
  # NAT Gateway Configuration
  enable_nat_gateway = var.enable_nat_gateway
  single_nat_gateway = var.single_nat_gateway
  
  # DNS Configuration
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  flow_log_retention_in_days          = var.log_retention_days
  
  # VPC Endpoints for AWS Services
  enable_s3_endpoint          = true
  enable_dynamodb_endpoint    = true
  enable_lambda_endpoint      = true
  enable_secretsmanager_endpoint = true
  enable_ssm_endpoint         = true
  enable_ec2_endpoint         = true
  
  # Public subnet tags for Load Balancers
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  
  # Private subnet tags
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
  
  tags = local.common_tags
}

# Security Group for Lambda Functions
resource "aws_security_group" "lambda" {
  name_prefix = "${local.name_prefix}-lambda-"
  description = "Security group for Pat Lambda functions"
  vpc_id      = module.vpc.vpc_id
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-lambda-sg"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for API Gateway VPC Link
resource "aws_security_group" "api_gateway" {
  name_prefix = "${local.name_prefix}-apigw-"
  description = "Security group for Pat API Gateway VPC Link"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS from anywhere"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-apigw-sg"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

# Network ACLs for additional security
resource "aws_network_acl_rule" "private_ingress_vpc" {
  network_acl_id = module.vpc.default_network_acl_id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = 0
  to_port        = 0
}

# VPC Endpoints Security Group
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${local.name_prefix}-vpce-"
  description = "Security group for VPC endpoints"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "Allow HTTPS from Lambda functions"
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce-sg"
  })
}