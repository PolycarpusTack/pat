# SQS Queues for Pat

# Email Processing Queue
resource "aws_sqs_queue" "email_processing" {
  name                       = "${local.name_prefix}-email-processing"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600 # 14 days
  max_message_size          = 262144  # 256 KB
  delay_seconds             = 0
  receive_wait_time_seconds = 20      # Long polling
  
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.email_processing_dlq.arn
    maxReceiveCount     = 3
  })
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-email-processing"
  })
}

# Dead Letter Queue for Email Processing
resource "aws_sqs_queue" "email_processing_dlq" {
  name                       = "${local.name_prefix}-email-processing-dlq"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600 # 14 days
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-email-processing-dlq"
  })
}

# Notification Queue
resource "aws_sqs_queue" "notifications" {
  name                       = "${local.name_prefix}-notifications"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 86400 # 1 day
  delay_seconds             = 0
  receive_wait_time_seconds = 10
  
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.notifications_dlq.arn
    maxReceiveCount     = 3
  })
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-notifications"
  })
}

# Dead Letter Queue for Notifications
resource "aws_sqs_queue" "notifications_dlq" {
  name                       = "${local.name_prefix}-notifications-dlq"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 345600 # 4 days
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-notifications-dlq"
  })
}

# Queue for Plugin Execution
resource "aws_sqs_queue" "plugin_execution" {
  name                       = "${local.name_prefix}-plugin-execution"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400 # 1 day
  delay_seconds             = 0
  receive_wait_time_seconds = 10
  
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.plugin_execution_dlq.arn
    maxReceiveCount     = 2
  })
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-plugin-execution"
  })
}

# Dead Letter Queue for Plugin Execution
resource "aws_sqs_queue" "plugin_execution_dlq" {
  name                       = "${local.name_prefix}-plugin-execution-dlq"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600 # 4 days
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-plugin-execution-dlq"
  })
}

# Queue Policies
data "aws_iam_policy_document" "sqs_policy" {
  statement {
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "sns.amazonaws.com"]
    }
    
    actions = [
      "sqs:SendMessage"
    ]
    
    resources = [
      aws_sqs_queue.email_processing.arn,
      aws_sqs_queue.notifications.arn,
      aws_sqs_queue.plugin_execution.arn
    ]
    
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/${local.name_prefix}-*"]
    }
  }
}

resource "aws_sqs_queue_policy" "email_processing" {
  queue_url = aws_sqs_queue.email_processing.id
  policy    = data.aws_iam_policy_document.sqs_policy.json
}

resource "aws_sqs_queue_policy" "notifications" {
  queue_url = aws_sqs_queue.notifications.id
  policy    = data.aws_iam_policy_document.sqs_policy.json
}

resource "aws_sqs_queue_policy" "plugin_execution" {
  queue_url = aws_sqs_queue.plugin_execution.id
  policy    = data.aws_iam_policy_document.sqs_policy.json
}