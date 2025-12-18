# Production environment configuration
# Consistent with layerv/traefik-plugins terraform patterns
#
# WARNING: Deployment blocked by default. See README.md for instructions.

environment    = "prod"
aws_region     = "us-east-2"
aws_account_id = "REPLACE_WITH_PROD_ACCOUNT_ID" # TODO: Set actual prod account ID
domain_name    = "nhp.layerv.ai"
hosted_zone    = "layerv.ai" # Hosted in layerv-mgmt account - requires cross-account DNS access
multi_tenant   = true
min_capacity   = 3
max_capacity   = 10
vpc_cidr       = "10.200.0.0/16" # Different CIDR from staging

# Multi-account config: prod pulls images from staging account's ECR
is_primary_account = false
primary_account_id = "767397897469" # Staging (layerv) account ID

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac  = true
acme_email = "admin@layerv.ai"

# CloudFront + WAF for DDoS protection (recommended for production)
enable_cloudfront = true

# Terraform state bucket for GitHub Actions permissions
# TODO: Set to the prod account's state bucket when account is configured
terraform_state_bucket = ""
terraform_lock_table   = "terraform-state-lock"

# Slack notifications via AWS Chatbot
# Note: Requires separate Chatbot authorization in prod AWS account
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C09UP62A8F4" # #all-layerv

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
