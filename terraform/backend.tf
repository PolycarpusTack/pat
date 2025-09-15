# Terraform Backend Configuration
# This file should be customized per environment

terraform {
  backend "s3" {
    # bucket         = "pat-terraform-state-{account-id}"
    # key            = "pat/{environment}/terraform.tfstate"
    # region         = "us-east-1"
    # encrypt        = true
    # kms_key_id     = "arn:aws:kms:us-east-1:{account-id}:key/{key-id}"
    # dynamodb_table = "pat-terraform-locks"
  }
}

# Note: Before using this backend, you need to:
# 1. Create the S3 bucket for state storage
# 2. Create the DynamoDB table for state locking
# 3. Create the KMS key for state encryption
# 4. Update the values above with your specific configuration
# 5. Run: terraform init -backend-config="bucket=your-bucket-name" ...