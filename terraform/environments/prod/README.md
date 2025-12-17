# Production Environment - DEPLOYMENT BLOCKED BY DEFAULT

## Safeguards

This environment has safeguards to prevent accidental deployment:

1. **Required confirmation variable**: You must explicitly set:
   ```
   confirm_prod_deployment = "yes-deploy-to-production"
   ```

2. **Separate AWS account**: Uses `layerv-prod` profile (not `layerv`)

3. **Separate state bucket**: Uses `layerv-prod-terraform-state` bucket

## To Deploy (when ready)

```bash
# Option 1: Add to terraform.tfvars
echo 'confirm_prod_deployment = "yes-deploy-to-production"' >> terraform.tfvars
terraform apply

# Option 2: Pass via command line
terraform apply -var='confirm_prod_deployment=yes-deploy-to-production'
```

## Pre-requisites

Before deploying to prod:

1. Staging must be fully tested and working
2. S3 bucket `layerv-prod-terraform-state` must exist in prod account
3. DynamoDB table `terraform-locks` must exist in prod account
4. AWS profile `layerv-prod` must be configured locally
