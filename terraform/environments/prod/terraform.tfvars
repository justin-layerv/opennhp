# Production environment configuration
# Consistent with layerv/traefik-plugins terraform patterns
#
# WARNING: Deployment blocked by default. See README.md for instructions.

environment    = "prod"
aws_region     = "us-east-2"
aws_account_id = "REPLACE_WITH_PROD_ACCOUNT_ID"  # TODO: Set actual prod account ID
domain_name    = "nhp.layerv.ai"
multi_tenant   = true
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.200.0.0/16"  # Different CIDR from staging

# Multi-account config: prod pulls images from staging account's ECR
is_primary_account = false
primary_account_id = "767397897469"  # Staging (layerv) account ID

tags = {}
