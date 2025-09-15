# CloudFront Distribution for Pat

# Origin Access Identity for S3
resource "aws_cloudfront_origin_access_identity" "attachments" {
  comment = "OAI for ${local.name_prefix} attachments"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "attachments" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${local.name_prefix} attachments CDN"
  default_root_object = "index.html"
  price_class         = var.environment == "prod" ? "PriceClass_All" : "PriceClass_100"
  
  origin {
    domain_name = aws_s3_bucket.attachments.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.attachments.id}"
    
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.attachments.cloudfront_access_identity_path
    }
  }
  
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.attachments.id}"
    
    forwarded_values {
      query_string = false
      headers      = ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"]
      
      cookies {
        forward = "none"
      }
    }
    
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    
    # Lambda@Edge for authentication (if needed)
    # lambda_function_association {
    #   event_type = "viewer-request"
    #   lambda_arn = aws_lambda_function.edge_auth.qualified_arn
    # }
  }
  
  # Custom error pages
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/error.html"
  }
  
  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/error.html"
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
  }
  
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-attachments-cdn"
  })
}

# S3 Bucket for CloudFront Logs
resource "aws_s3_bucket" "logs" {
  bucket = "${local.name_prefix}-logs-${random_string.suffix.result}"
  
  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-logs"
    Purpose = "CloudFront and ALB logs"
  })
}

# Logs Bucket ACL
resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "log-delivery-write"
}

# Logs Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    
    expiration {
      days = var.log_retention_days
    }
  }
}

# Logs Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}