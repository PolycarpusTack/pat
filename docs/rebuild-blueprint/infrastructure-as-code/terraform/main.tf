terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "development"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "mailhog"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# VPC Configuration
resource "aws_vpc" "mailhog" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-vpc"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Internet Gateway
resource "aws_internet_gateway" "mailhog" {
  vpc_id = aws_vpc.mailhog.id
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-igw"
    Environment = var.environment
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.mailhog.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-public-${count.index + 1}"
    Environment = var.environment
    Type        = "public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.mailhog.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-private-${count.index + 1}"
    Environment = var.environment
    Type        = "private"
  }
}

# Data source for AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Route Table for Public Subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.mailhog.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mailhog.id
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-public-rt"
    Environment = var.environment
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Security Group for MailHog
resource "aws_security_group" "mailhog" {
  name        = "${var.project_name}-${var.environment}-sg"
  description = "Security group for MailHog"
  vpc_id      = aws_vpc.mailhog.id
  
  # SMTP Port
  ingress {
    description = "SMTP"
    from_port   = 1025
    to_port     = 1025
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # HTTP/Web UI Port
  ingress {
    description = "HTTP"
    from_port   = 8025
    to_port     = 8025
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-sg"
    Environment = var.environment
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "mailhog" {
  name = "${var.project_name}-${var.environment}"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "mailhog" {
  family                   = "${var.project_name}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
  
  container_definitions = jsonencode([
    {
      name  = "mailhog"
      image = "mailhog/mailhog:v1.0.1"
      
      portMappings = [
        {
          containerPort = 1025
          protocol      = "tcp"
        },
        {
          containerPort = 8025
          protocol      = "tcp"
        }
      ]
      
      environment = [
        {
          name  = "MH_STORAGE"
          value = "memory"
        },
        {
          name  = "MH_CORS_ORIGIN"
          value = "*"
        }
      ]
      
      healthCheck = {
        command     = ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:8025/api/v2/messages?limit=1 || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.mailhog.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "mailhog" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = 7
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Roles
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.project_name}-${var.environment}-ecs-execution-role"
  
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
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  role       = aws_iam_role.ecs_execution_role.name
}

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-${var.environment}-ecs-task-role"
  
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
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# Application Load Balancer
resource "aws_lb" "mailhog" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  
  enable_deletion_protection = false
  enable_http2              = true
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.mailhog.id
  
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-alb-sg"
    Environment = var.environment
  }
}

# Target Groups
resource "aws_lb_target_group" "mailhog_web" {
  name        = "${var.project_name}-${var.environment}-web"
  port        = 8025
  protocol    = "HTTP"
  vpc_id      = aws_vpc.mailhog.id
  target_type = "ip"
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/v2/messages?limit=1"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# ALB Listeners
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.mailhog.arn
  port              = "80"
  protocol          = "HTTP"
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mailhog_web.arn
  }
}

# ECS Service
resource "aws_ecs_service" "mailhog" {
  name            = "${var.project_name}-${var.environment}"
  cluster         = aws_ecs_cluster.mailhog.id
  task_definition = aws_ecs_task_definition.mailhog.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  
  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.mailhog.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = aws_lb_target_group.mailhog_web.arn
    container_name   = "mailhog"
    container_port   = 8025
  }
  
  depends_on = [
    aws_lb_listener.http
  ]
  
  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# Auto Scaling
resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = 5
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.mailhog.name}/${aws_ecs_service.mailhog.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.project_name}-${var.environment}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Outputs
output "alb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.mailhog.dns_name
}

output "smtp_endpoint" {
  description = "SMTP endpoint (configure your app to use this)"
  value       = "${aws_lb.mailhog.dns_name}:1025"
}

output "web_ui_url" {
  description = "Web UI URL"
  value       = "http://${aws_lb.mailhog.dns_name}"
}