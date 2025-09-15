# AWS EventBridge Configuration for Pat

# Custom Event Bus
resource "aws_cloudwatch_event_bus" "pat" {
  name = "${local.name_prefix}-events"
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-event-bus"
  })
}

# Event Archive for replay capability
resource "aws_cloudwatch_event_archive" "pat" {
  name             = "${local.name_prefix}-archive"
  event_source_arn = aws_cloudwatch_event_bus.pat.arn
  retention_days   = 7
  description      = "Archive for Pat events"
  
  event_pattern = jsonencode({
    account = [data.aws_caller_identity.current.account_id]
  })
}

# Rule: Email Received
resource "aws_cloudwatch_event_rule" "email_received" {
  name           = "${local.name_prefix}-email-received"
  description    = "Triggered when a new email is received"
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  
  event_pattern = jsonencode({
    source      = ["pat.smtp"]
    detail-type = ["Email Received"]
  })
  
  tags = local.common_tags
}

# Target: Email Processing Lambda
resource "aws_cloudwatch_event_target" "email_processor" {
  rule           = aws_cloudwatch_event_rule.email_received.name
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  target_id      = "EmailProcessorLambda"
  arn            = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-email-processor"
  
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }
  
  dead_letter_config {
    arn = aws_sqs_queue.eventbridge_dlq.arn
  }
}

# Rule: Email Processed
resource "aws_cloudwatch_event_rule" "email_processed" {
  name           = "${local.name_prefix}-email-processed"
  description    = "Triggered when email processing is complete"
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  
  event_pattern = jsonencode({
    source      = ["pat.processor"]
    detail-type = ["Email Processed"]
  })
  
  tags = local.common_tags
}

# Target: Notification Service
resource "aws_cloudwatch_event_target" "notification_service" {
  rule           = aws_cloudwatch_event_rule.email_processed.name
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  target_id      = "NotificationService"
  arn            = aws_sqs_queue.notifications.arn
  
  sqs_target {
    message_group_id = "email-notifications"
  }
}

# Rule: Email Validation Required
resource "aws_cloudwatch_event_rule" "email_validation" {
  name           = "${local.name_prefix}-email-validation"
  description    = "Triggered when email needs validation"
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  
  event_pattern = jsonencode({
    source      = ["pat.processor"]
    detail-type = ["Validation Required"]
  })
  
  tags = local.common_tags
}

# Target: Validation Lambda
resource "aws_cloudwatch_event_target" "validation_lambda" {
  rule           = aws_cloudwatch_event_rule.email_validation.name
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  target_id      = "ValidationLambda"
  arn            = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-email-validator"
  
  input_transformer {
    input_paths = {
      emailId = "$.detail.emailId"
      rules   = "$.detail.validationRules"
    }
    
    input_template = jsonencode({
      emailId = "<emailId>"
      rules   = "<rules>"
    })
  }
}

# Rule: Plugin Execution
resource "aws_cloudwatch_event_rule" "plugin_execution" {
  name           = "${local.name_prefix}-plugin-execution"
  description    = "Triggered when plugin needs to be executed"
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  
  event_pattern = jsonencode({
    source      = ["pat.plugins"]
    detail-type = ["Plugin Execution Required"]
  })
  
  tags = local.common_tags
}

# Target: Plugin Execution Queue
resource "aws_cloudwatch_event_target" "plugin_queue" {
  rule           = aws_cloudwatch_event_rule.plugin_execution.name
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  target_id      = "PluginExecutionQueue"
  arn            = aws_sqs_queue.plugin_execution.arn
}

# Rule: Workflow Triggered
resource "aws_cloudwatch_event_rule" "workflow_triggered" {
  name           = "${local.name_prefix}-workflow-triggered"
  description    = "Triggered when a workflow needs to be executed"
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  
  event_pattern = jsonencode({
    source      = ["pat.workflows"]
    detail-type = ["Workflow Triggered"]
  })
  
  tags = local.common_tags
}

# Target: Step Functions for Workflow
resource "aws_cloudwatch_event_target" "workflow_stepfunctions" {
  rule           = aws_cloudwatch_event_rule.workflow_triggered.name
  event_bus_name = aws_cloudwatch_event_bus.pat.name
  target_id      = "WorkflowStepFunctions"
  arn            = aws_sfn_state_machine.workflow_executor.arn
  role_arn       = aws_iam_role.eventbridge_stepfunctions.arn
  
  input_transformer {
    input_paths = {
      workflowId = "$.detail.workflowId"
      context    = "$.detail.context"
    }
    
    input_template = jsonencode({
      workflowId = "<workflowId>"
      context    = "<context>"
    })
  }
}

# Rule: Scheduled Tasks
resource "aws_cloudwatch_event_rule" "scheduled_cleanup" {
  name                = "${local.name_prefix}-scheduled-cleanup"
  description         = "Daily cleanup of old emails"
  schedule_expression = "cron(0 2 * * ? *)"
  
  tags = local.common_tags
}

# Target: Cleanup Lambda
resource "aws_cloudwatch_event_target" "cleanup_lambda" {
  rule      = aws_cloudwatch_event_rule.scheduled_cleanup.name
  target_id = "CleanupLambda"
  arn       = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-cleanup"
}

# DLQ for EventBridge
resource "aws_sqs_queue" "eventbridge_dlq" {
  name                       = "${local.name_prefix}-eventbridge-dlq"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600 # 14 days
  
  kms_master_key_id                 = aws_kms_key.pat.id
  kms_data_key_reuse_period_seconds = 300
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-eventbridge-dlq"
  })
}

# IAM Role for EventBridge to Step Functions
resource "aws_iam_role" "eventbridge_stepfunctions" {
  name = "${local.name_prefix}-eventbridge-stepfunctions"
  
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

# IAM Policy for EventBridge to Step Functions
resource "aws_iam_role_policy" "eventbridge_stepfunctions" {
  name = "${local.name_prefix}-eventbridge-stepfunctions"
  role = aws_iam_role.eventbridge_stepfunctions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "states:StartExecution"
        Resource = aws_sfn_state_machine.workflow_executor.arn
      }
    ]
  })
}

# Step Functions State Machine for Workflows
resource "aws_sfn_state_machine" "workflow_executor" {
  name     = "${local.name_prefix}-workflow-executor"
  role_arn = aws_iam_role.stepfunctions.arn
  
  definition = jsonencode({
    Comment = "Pat Workflow Executor"
    StartAt = "LoadWorkflow"
    States = {
      LoadWorkflow = {
        Type     = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-load-workflow"
        Next     = "ExecuteSteps"
      }
      ExecuteSteps = {
        Type = "Map"
        ItemsPath = "$.steps"
        MaxConcurrency = 5
        Iterator = {
          StartAt = "ProcessStep"
          States = {
            ProcessStep = {
              Type = "Task"
              Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-process-step"
              End = true
            }
          }
        }
        Next = "CompleteWorkflow"
      }
      CompleteWorkflow = {
        Type = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-complete-workflow"
        End = true
      }
    }
  })
  
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.stepfunctions.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }
  
  tracing_configuration {
    enabled = true
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-workflow-executor"
  })
}

# IAM Role for Step Functions
resource "aws_iam_role" "stepfunctions" {
  name = "${local.name_prefix}-stepfunctions"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

# IAM Policy for Step Functions
resource "aws_iam_role_policy" "stepfunctions" {
  name = "${local.name_prefix}-stepfunctions"
  role = aws_iam_role.stepfunctions.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${local.name_prefix}-*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for Step Functions
resource "aws_cloudwatch_log_group" "stepfunctions" {
  name              = "/aws/stepfunctions/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn
  
  tags = local.common_tags
}