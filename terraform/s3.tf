# S3 Buckets for Pat

# Email Attachments Bucket
resource "aws_s3_bucket" "attachments" {
  bucket = "${local.name_prefix}-attachments-${random_string.suffix.result}"
  
  tags = merge(local.common_tags, {
    Name        = "${local.name_prefix}-attachments"
    Purpose     = "Email attachments storage"
  })
}

# Attachments Bucket Versioning
resource "aws_s3_bucket_versioning" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  
  versioning_configuration {
    status = var.s3_versioning_enabled ? "Enabled" : "Disabled"
  }
}

# Attachments Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pat.arn
    }
    bucket_key_enabled = true
  }
}

# Attachments Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  
  rule {
    id     = "transition-to-ia"
    status = "Enabled"
    
    transition {
      days          = var.s3_lifecycle_days
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = var.s3_lifecycle_days * 3
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
  
  rule {
    id     = "delete-incomplete-uploads"
    status = "Enabled"
    
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Attachments Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Attachments Bucket Policy
resource "aws_s3_bucket_policy" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}

# Lambda Deployment Bucket
resource "aws_s3_bucket" "lambda_deployments" {
  bucket = "${local.name_prefix}-lambda-deployments-${random_string.suffix.result}"
  
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-lambda-deployments"
    Purpose = "Lambda function deployment packages"
  })
}

# Lambda Deployment Bucket Versioning
resource "aws_s3_bucket_versioning" "lambda_deployments" {
  bucket = aws_s3_bucket.lambda_deployments.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Lambda Deployment Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "lambda_deployments" {
  bucket = aws_s3_bucket.lambda_deployments.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lambda Deployment Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "lambda_deployments" {
  bucket = aws_s3_bucket.lambda_deployments.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Backup Bucket
resource "aws_s3_bucket" "backups" {
  bucket = "${local.name_prefix}-backups-${random_string.suffix.result}"
  
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-backups"
    Purpose = "System backups"
  })
}

# Backup Bucket Versioning
resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Backup Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pat.arn
    }
    bucket_key_enabled = true
  }
}

# Backup Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  rule {
    id     = "expire-old-backups"
    status = "Enabled"
    
    expiration {
      days = 90
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Backup Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Backup Bucket Replication (for production)
resource "aws_s3_bucket_replication_configuration" "backups" {
  count = var.environment == "prod" ? 1 : 0
  
  role   = aws_iam_role.s3_replication[0].arn
  bucket = aws_s3_bucket.backups.id
  
  rule {
    id     = "replicate-all"
    status = "Enabled"
    
    destination {
      bucket        = aws_s3_bucket.backups_replica[0].arn
      storage_class = "STANDARD_IA"
      
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.pat_replica[0].arn
      }
    }
  }
  
  depends_on = [aws_s3_bucket_versioning.backups]
}