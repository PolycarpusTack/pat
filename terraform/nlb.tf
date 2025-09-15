# Network Load Balancer for SMTP Traffic

# Elastic IPs for NLB (static IPs for MX records)
resource "aws_eip" "nlb" {
  count  = length(module.vpc.public_subnets)
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nlb-eip-${count.index + 1}"
  })
}

# Network Load Balancer
resource "aws_lb" "smtp" {
  name               = "${local.name_prefix}-smtp"
  internal           = false
  load_balancer_type = "network"
  
  enable_deletion_protection = var.environment == "prod"
  enable_cross_zone_load_balancing = true

  # Assign static IPs to each subnet
  dynamic "subnet_mapping" {
    for_each = range(length(module.vpc.public_subnets))
    content {
      subnet_id     = module.vpc.public_subnets[subnet_mapping.value]
      allocation_id = aws_eip.nlb[subnet_mapping.value].id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-nlb"
  })
}

# Target Group for SMTP (Port 25)
resource "aws_lb_target_group" "smtp_25" {
  name        = "${local.name_prefix}-smtp-25"
  port        = 25
  protocol    = "TCP"
  vpc_id      = module.vpc.vpc_id
  target_type = "lambda"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    protocol            = "TCP"
  }

  deregistration_delay = 30

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-25-tg"
  })
}

# Target Group for SMTP Submission (Port 587)
resource "aws_lb_target_group" "smtp_587" {
  name        = "${local.name_prefix}-smtp-587"
  port        = 587
  protocol    = "TCP"
  vpc_id      = module.vpc.vpc_id
  target_type = "lambda"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    protocol            = "TCP"
  }

  deregistration_delay = 30

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-587-tg"
  })
}

# Target Group for SMTPS (Port 465)
resource "aws_lb_target_group" "smtp_465" {
  name        = "${local.name_prefix}-smtp-465"
  port        = 465
  protocol    = "TLS"
  vpc_id      = module.vpc.vpc_id
  target_type = "lambda"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    protocol            = "TCP"
  }

  deregistration_delay = 30

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-465-tg"
  })
}

# NLB Listeners
resource "aws_lb_listener" "smtp_25" {
  load_balancer_arn = aws_lb.smtp.arn
  port              = 25
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.smtp_25.arn
  }
}

resource "aws_lb_listener" "smtp_587" {
  load_balancer_arn = aws_lb.smtp.arn
  port              = 587
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.smtp_587.arn
  }
}

resource "aws_lb_listener" "smtp_465" {
  load_balancer_arn = aws_lb.smtp.arn
  port              = 465
  protocol          = "TLS"
  
  certificate_arn = aws_acm_certificate.smtp.arn
  alpn_policy     = "None"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.smtp_465.arn
  }
}

# Lambda permission for NLB
resource "aws_lambda_permission" "nlb_smtp_25" {
  statement_id  = "AllowNLBInvoke25"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.smtp_handler.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.smtp_25.arn
}

resource "aws_lambda_permission" "nlb_smtp_587" {
  statement_id  = "AllowNLBInvoke587"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.smtp_handler.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.smtp_587.arn
}

resource "aws_lambda_permission" "nlb_smtp_465" {
  statement_id  = "AllowNLBInvoke465"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.smtp_handler.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.smtp_465.arn
}

# Target Group Attachments
resource "aws_lb_target_group_attachment" "smtp_25" {
  target_group_arn = aws_lb_target_group.smtp_25.arn
  target_id        = aws_lambda_function.smtp_handler.arn
}

resource "aws_lb_target_group_attachment" "smtp_587" {
  target_group_arn = aws_lb_target_group.smtp_587.arn
  target_id        = aws_lambda_function.smtp_handler.arn
}

resource "aws_lb_target_group_attachment" "smtp_465" {
  target_group_arn = aws_lb_target_group.smtp_465.arn
  target_id        = aws_lambda_function.smtp_handler.arn
}

# ACM Certificate for SMTPS
resource "aws_acm_certificate" "smtp" {
  domain_name       = "smtp.${var.domain_name}"
  validation_method = "DNS"

  subject_alternative_names = [
    "mx.${var.domain_name}",
    "mail.${var.domain_name}",
    "smtp-*.${var.domain_name}",
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-cert"
  })
}

# Route53 records for certificate validation
resource "aws_route53_record" "smtp_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.smtp.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

# Certificate validation
resource "aws_acm_certificate_validation" "smtp" {
  certificate_arn         = aws_acm_certificate.smtp.arn
  validation_record_fqdns = [for record in aws_route53_record.smtp_cert_validation : record.fqdn]
}

# VPC Flow Logs for NLB
resource "aws_flow_log" "nlb" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = module.vpc.vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-nlb-flow-logs"
  })
}

# CloudWatch Log Group for Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${local.name_prefix}/flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# IAM Role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name_prefix}-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Alarms for NLB
resource "aws_cloudwatch_metric_alarm" "nlb_unhealthy_hosts" {
  alarm_name          = "${local.name_prefix}-nlb-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "0"
  alarm_description   = "NLB has unhealthy hosts"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.smtp.arn_suffix
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "nlb_connection_errors" {
  alarm_name          = "${local.name_prefix}-nlb-connection-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetConnectionErrorCount"
  namespace           = "AWS/NetworkELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "High NLB connection errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = aws_lb.smtp.arn_suffix
  }

  tags = local.common_tags
}

# Outputs
output "nlb_dns_name" {
  value = aws_lb.smtp.dns_name
}

output "nlb_static_ips" {
  value = aws_eip.nlb[*].public_ip
}

output "smtp_endpoints" {
  value = {
    smtp    = "${aws_lb.smtp.dns_name}:25"
    submission = "${aws_lb.smtp.dns_name}:587"
    smtps   = "${aws_lb.smtp.dns_name}:465"
  }
}