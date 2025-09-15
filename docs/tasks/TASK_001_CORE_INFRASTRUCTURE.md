# TASK 001: Core Infrastructure Setup

**Stream**: Backend Infrastructure  
**Dependencies**: None  
**Can Run Parallel With**: TASK_002, TASK_003, TASK_004  
**Estimated Duration**: 1 week  
**Team**: 1 Backend Engineer

## Objectives
Set up the foundational infrastructure for Pat's serverless architecture.

## Tasks

### 1. Repository and CI/CD Setup
- [ ] Initialize Git repository with proper structure
- [ ] Set up GitHub Actions for CI/CD
- [ ] Configure branch protection rules
- [ ] Create development, staging, production branches
- [ ] Set up semantic versioning

### 2. AWS Infrastructure (Terraform)
```hcl
# Create terraform/main.tf
- [ ] Configure AWS provider
- [ ] Set up S3 backend for state
- [ ] Create VPC with public/private subnets
- [ ] Set up security groups
- [ ] Configure IAM roles for Lambda
```

### 3. Serverless Framework Setup
```yaml
# serverless.yml
- [ ] Install Serverless Framework
- [ ] Configure AWS Lambda functions structure
- [ ] Set up API Gateway
- [ ] Configure environment stages
- [ ] Set up CloudWatch logging
```

### 4. Container Registry
- [ ] Set up ECR repositories
- [ ] Create base Docker images
- [ ] Configure automated scanning
- [ ] Set up image lifecycle policies

### 5. Secrets Management
- [ ] Set up AWS Secrets Manager
- [ ] Create secret rotation Lambda
- [ ] Configure KMS keys
- [ ] Document secret naming conventions

## Success Criteria
- [ ] Can deploy Lambda function via CI/CD
- [ ] Terraform can provision all resources
- [ ] Secrets are properly managed
- [ ] All infrastructure is tagged correctly

## Output Artifacts
- `terraform/` directory with all IaC
- `serverless.yml` configuration
- CI/CD pipeline configuration
- Infrastructure documentation