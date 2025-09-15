# API Gateway for GraphQL

# API Gateway REST API
resource "aws_api_gateway_rest_api" "pat" {
  name        = "${local.name_prefix}-api"
  description = "Pat Platform GraphQL API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-api-gateway"
  })
}

# API Gateway Resource for GraphQL
resource "aws_api_gateway_resource" "graphql" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  parent_id   = aws_api_gateway_rest_api.pat.root_resource_id
  path_part   = "graphql"
}

# API Gateway Method - POST
resource "aws_api_gateway_method" "graphql_post" {
  rest_api_id   = aws_api_gateway_rest_api.pat.id
  resource_id   = aws_api_gateway_resource.graphql.id
  http_method   = "POST"
  authorization = "NONE"

  request_parameters = {
    "method.request.header.Authorization" = false
  }
}

# API Gateway Method - OPTIONS (for CORS)
resource "aws_api_gateway_method" "graphql_options" {
  rest_api_id   = aws_api_gateway_rest_api.pat.id
  resource_id   = aws_api_gateway_resource.graphql.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

# Lambda integration for GraphQL
resource "aws_api_gateway_integration" "graphql_post" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  resource_id = aws_api_gateway_resource.graphql.id
  http_method = aws_api_gateway_method.graphql_post.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.graphql.invoke_arn

  depends_on = [aws_api_gateway_method.graphql_post]
}

# OPTIONS integration for CORS
resource "aws_api_gateway_integration" "graphql_options" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  resource_id = aws_api_gateway_resource.graphql.id
  http_method = aws_api_gateway_method.graphql_options.http_method

  type = "MOCK"

  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }

  depends_on = [aws_api_gateway_method.graphql_options]
}

# Method responses for POST
resource "aws_api_gateway_method_response" "graphql_post" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  resource_id = aws_api_gateway_resource.graphql.id
  http_method = aws_api_gateway_method.graphql_post.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
  }

  depends_on = [aws_api_gateway_method.graphql_post]
}

# Method responses for OPTIONS
resource "aws_api_gateway_method_response" "graphql_options" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  resource_id = aws_api_gateway_resource.graphql.id
  http_method = aws_api_gateway_method.graphql_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
  }

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.graphql_options]
}

# Integration responses for OPTIONS
resource "aws_api_gateway_integration_response" "graphql_options" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  resource_id = aws_api_gateway_resource.graphql.id
  http_method = aws_api_gateway_method.graphql_options.http_method
  status_code = aws_api_gateway_method_response.graphql_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,OPTIONS,POST'"
  }

  depends_on = [
    aws_api_gateway_method_response.graphql_options,
    aws_api_gateway_integration.graphql_options,
  ]
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "pat" {
  rest_api_id = aws_api_gateway_rest_api.pat.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.graphql.id,
      aws_api_gateway_method.graphql_post.id,
      aws_api_gateway_method.graphql_options.id,
      aws_api_gateway_integration.graphql_post.id,
      aws_api_gateway_integration.graphql_options.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.graphql_post,
    aws_api_gateway_integration.graphql_options,
  ]
}

# API Gateway Stage
resource "aws_api_gateway_stage" "pat" {
  deployment_id = aws_api_gateway_deployment.pat.id
  rest_api_id   = aws_api_gateway_rest_api.pat.id
  stage_name    = var.environment

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      error          = "$context.error.message"
    })
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-api-stage-${var.environment}"
  })
}

# API Gateway Method Settings
resource "aws_api_gateway_method_settings" "pat" {
  rest_api_id = aws_api_gateway_rest_api.pat.id
  stage_name  = aws_api_gateway_stage.pat.stage_name
  method_path = "*/*"

  settings = {
    metrics_enabled        = true
    logging_level          = "INFO"
    data_trace_enabled     = var.environment != "prod"
    throttling_rate_limit  = 1000
    throttling_burst_limit = 2000
  }
}

# API Gateway Usage Plan
resource "aws_api_gateway_usage_plan" "pat" {
  name        = "${local.name_prefix}-usage-plan"
  description = "Usage plan for Pat API"

  api_stages {
    api_id = aws_api_gateway_rest_api.pat.id
    stage  = aws_api_gateway_stage.pat.stage_name
  }

  quota_settings {
    limit  = 1000000  # 1 million requests
    period = "MONTH"
  }

  throttle_settings {
    rate_limit  = 1000
    burst_limit = 2000
  }

  tags = local.common_tags
}

# API Keys
resource "aws_api_gateway_api_key" "default" {
  name        = "${local.name_prefix}-default-key"
  description = "Default API key for Pat platform"
  tags        = local.common_tags
}

# Usage Plan Key
resource "aws_api_gateway_usage_plan_key" "default" {
  key_id        = aws_api_gateway_api_key.default.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.pat.id
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pat.arn

  tags = local.common_tags
}

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.graphql.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.pat.execution_arn}/*/*"
}

# WAF Web ACL for API Gateway
resource "aws_wafv2_web_acl" "api_gateway" {
  name  = "${local.name_prefix}-api-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # SQL injection protection
  rule {
    name     = "SQLiProtection"
    priority = 2

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          body {}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-sqli"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

# Associate WAF with API Gateway
resource "aws_wafv2_web_acl_association" "api_gateway" {
  resource_arn = aws_api_gateway_stage.pat.arn
  web_acl_arn  = aws_wafv2_web_acl.api_gateway.arn
}

# Outputs
output "api_gateway_url" {
  value = aws_api_gateway_stage.pat.invoke_url
}

output "api_gateway_key" {
  value     = aws_api_gateway_api_key.default.value
  sensitive = true
}

output "graphql_endpoint" {
  value = "${aws_api_gateway_stage.pat.invoke_url}/graphql"
}