# KMS Keys for Pat

# Primary KMS Key
resource "aws_kms_key" "pat" {
  description             = "KMS key for Pat email testing platform"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_key_policy.json
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kms-key"
  })
}

# KMS Key Alias
resource "aws_kms_alias" "pat" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.pat.key_id
}

# Replica KMS Key for Production
resource "aws_kms_key" "pat_replica" {
  provider = aws.replica
  count    = var.environment == "prod" ? 1 : 0
  
  description             = "Replica KMS key for Pat email testing platform"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kms-key-replica"
  })
}

# Replica KMS Key Alias
resource "aws_kms_alias" "pat_replica" {
  provider = aws.replica
  count    = var.environment == "prod" ? 1 : 0
  
  name          = "alias/${local.name_prefix}-replica"
  target_key_id = aws_kms_key.pat_replica[0].key_id
}