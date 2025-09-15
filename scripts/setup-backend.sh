#!/bin/bash
# Setup script for Terraform backend resources

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
AWS_REGION=${AWS_REGION:-"us-east-1"}
ENVIRONMENT=${ENVIRONMENT:-"dev"}
PROJECT="pat"

echo -e "${GREEN}Setting up Terraform backend for Pat Email Testing Platform${NC}"
echo "Region: $AWS_REGION"
echo "Environment: $ENVIRONMENT"

# Check AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}AWS credentials not configured. Please run 'aws configure'.${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS Account ID: $ACCOUNT_ID"

# Create S3 bucket for Terraform state
BUCKET_NAME="${PROJECT}-terraform-state-${ACCOUNT_ID}"
echo -e "\n${YELLOW}Creating S3 bucket for Terraform state: $BUCKET_NAME${NC}"

if aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    echo "Bucket already exists, skipping creation"
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION" \
        $(if [ "$AWS_REGION" != "us-east-1" ]; then echo "--create-bucket-configuration LocationConstraint=$AWS_REGION"; fi)
    
    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "$BUCKET_NAME" \
        --versioning-configuration Status=Enabled
    
    # Enable encryption
    aws s3api put-bucket-encryption \
        --bucket "$BUCKET_NAME" \
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }'
    
    # Block public access
    aws s3api put-public-access-block \
        --bucket "$BUCKET_NAME" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    
    echo -e "${GREEN}S3 bucket created successfully${NC}"
fi

# Create DynamoDB table for state locking
TABLE_NAME="${PROJECT}-terraform-locks"
echo -e "\n${YELLOW}Creating DynamoDB table for state locking: $TABLE_NAME${NC}"

if aws dynamodb describe-table --table-name "$TABLE_NAME" --region "$AWS_REGION" 2>/dev/null; then
    echo "Table already exists, skipping creation"
else
    aws dynamodb create-table \
        --table-name "$TABLE_NAME" \
        --attribute-definitions AttributeName=LockID,AttributeType=S \
        --key-schema AttributeName=LockID,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST \
        --region "$AWS_REGION" \
        --tags Key=Project,Value=$PROJECT Key=Environment,Value=$ENVIRONMENT
    
    echo -e "${GREEN}DynamoDB table created successfully${NC}"
fi

# Create backend configuration file
BACKEND_CONFIG="terraform/backend-config/${ENVIRONMENT}.hcl"
mkdir -p terraform/backend-config

cat > "$BACKEND_CONFIG" << EOF
bucket         = "${BUCKET_NAME}"
key            = "${PROJECT}/${ENVIRONMENT}/terraform.tfstate"
region         = "${AWS_REGION}"
encrypt        = true
dynamodb_table = "${TABLE_NAME}"
EOF

echo -e "\n${GREEN}Backend configuration created at: $BACKEND_CONFIG${NC}"

# Create terraform variables file
TFVARS_FILE="terraform/environments/${ENVIRONMENT}.tfvars"
mkdir -p terraform/environments

cat > "$TFVARS_FILE" << EOF
# Terraform variables for $ENVIRONMENT environment
aws_region  = "${AWS_REGION}"
environment = "${ENVIRONMENT}"
owner_email = "your-email@example.com" # UPDATE THIS

# VPC Configuration
vpc_cidr = "10.0.0.0/16"

# Lambda Configuration
lambda_memory_size = 512
lambda_timeout     = 30

# Cost Optimization
enable_spot_instances = $([ "$ENVIRONMENT" = "prod" ] && echo "false" || echo "true")

# Monitoring
enable_detailed_monitoring = $([ "$ENVIRONMENT" = "prod" ] && echo "true" || echo "false")
log_retention_days         = $([ "$ENVIRONMENT" = "prod" ] && echo "90" || echo "30")

# Additional tags
additional_tags = {
  ManagedBy   = "Terraform"
  CostCenter  = "Engineering"
}
EOF

echo -e "${GREEN}Terraform variables file created at: $TFVARS_FILE${NC}"
echo -e "${YELLOW}Please update the owner_email in the file before running Terraform${NC}"

# Initialize Terraform
echo -e "\n${YELLOW}Initializing Terraform...${NC}"
cd terraform
terraform init -backend-config="../$BACKEND_CONFIG"

echo -e "\n${GREEN}✅ Terraform backend setup complete!${NC}"
echo -e "\nNext steps:"
echo -e "1. Update owner_email in $TFVARS_FILE"
echo -e "2. Run: cd terraform && terraform plan -var-file=environments/${ENVIRONMENT}.tfvars"
echo -e "3. Run: terraform apply -var-file=environments/${ENVIRONMENT}.tfvars"