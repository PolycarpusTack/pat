# AWS SNS Configuration for Pat

# Main alerts topic
resource "aws_sns_topic" "alerts" {
  name              = "${local.name_prefix}-alerts"
  display_name      = "Pat Platform Alerts"
  kms_master_key_id = aws_kms_key.pat.id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-alerts"
  })
}

# Email alerts subscription (placeholder - update with actual email)
resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Critical alerts topic
resource "aws_sns_topic" "critical_alerts" {
  name              = "${local.name_prefix}-critical-alerts"
  display_name      = "Pat Critical Alerts"
  kms_master_key_id = aws_kms_key.pat.id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-critical-alerts"
  })
}

# Operations notifications topic
resource "aws_sns_topic" "operations" {
  name              = "${local.name_prefix}-operations"
  display_name      = "Pat Operations Notifications"
  kms_master_key_id = aws_kms_key.pat.id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-operations"
  })
}

# User notifications topic (for application notifications)
resource "aws_sns_topic" "user_notifications" {
  name              = "${local.name_prefix}-user-notifications"
  display_name      = "Pat User Notifications"
  kms_master_key_id = aws_kms_key.pat.id
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-user-notifications"
  })
}

# SNS topic policies
resource "aws_sns_topic_policy" "alerts_policy" {
  arn = aws_sns_topic.alerts.arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "cloudwatch.amazonaws.com",
            "events.amazonaws.com"
          ]
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# Outputs
output "sns_topics" {
  value = {
    alerts = {
      arn  = aws_sns_topic.alerts.arn
      name = aws_sns_topic.alerts.name
    }
    critical_alerts = {
      arn  = aws_sns_topic.critical_alerts.arn
      name = aws_sns_topic.critical_alerts.name
    }
    operations = {
      arn  = aws_sns_topic.operations.arn
      name = aws_sns_topic.operations.name
    }
    user_notifications = {
      arn  = aws_sns_topic.user_notifications.arn
      name = aws_sns_topic.user_notifications.name
    }
  }
}