# Staging environment configuration
# Consistent with layerv/traefik-plugins terraform patterns

environment    = "staging"
aws_region     = "us-east-2"
aws_account_id = "767397897469"
domain_name    = "staging.nhp.layerv.ai"
multi_tenant   = true
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.100.0.0/16"

# Multi-account config: staging owns ECR repositories
is_primary_account = true

tags = {}
