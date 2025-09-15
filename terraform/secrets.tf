# Secrets Manager for Pat

# Application Secrets
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${local.name_prefix}-app-secrets"
  description             = "Application secrets for Pat"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-app-secrets"
  })
}

# Initial secret values (to be updated manually)
resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  
  secret_string = jsonencode({
    jwt_secret     = random_password.jwt_secret.result
    api_key        = random_password.api_key.result
    encryption_key = random_password.encryption_key.result
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Database Secrets
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "${local.name_prefix}-db-credentials"
  description             = "Database credentials for Pat"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-credentials"
  })
}

# SMTP Credentials Secret
resource "aws_secretsmanager_secret" "smtp_credentials" {
  name                    = "${local.name_prefix}-smtp-credentials"
  description             = "SMTP credentials for Pat"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-smtp-credentials"
  })
}

# OAuth Secrets
resource "aws_secretsmanager_secret" "oauth_secrets" {
  name                    = "${local.name_prefix}-oauth-secrets"
  description             = "OAuth provider secrets for Pat"
  kms_key_id              = aws_kms_key.pat.id
  recovery_window_in_days = 7
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-oauth-secrets"
  })
}

# Generate random passwords
resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "random_password" "api_key" {
  length  = 32
  special = false
}

resource "random_password" "encryption_key" {
  length  = 32
  special = false
}

# Secret Rotation Lambda (if enabled)
resource "aws_secretsmanager_secret_rotation" "app_secrets" {
  count = var.enable_secret_rotation ? 1 : 0
  
  secret_id           = aws_secretsmanager_secret.app_secrets.id
  rotation_lambda_arn = aws_lambda_function.secret_rotation[0].arn
  
  rotation_rules {
    automatically_after_days = var.secret_rotation_days
  }
}