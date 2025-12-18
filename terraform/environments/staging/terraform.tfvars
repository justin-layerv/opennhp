# Staging environment configuration
# Consistent with layerv/traefik-plugins terraform patterns

environment    = "staging"
aws_region     = "us-east-2"
aws_account_id = "767397897469"
domain_name    = "nhp.layerv.xyz"
hosted_zone    = "layerv.xyz"
multi_tenant   = true
min_capacity   = 1
max_capacity   = 10
vpc_cidr       = "10.100.0.0/16"

# Multi-account config: staging owns ECR repositories
is_primary_account = true
# secondary_account_ids = ["PROD_ACCOUNT_ID"]  # TODO: Add prod account ID when created

# AC configuration (Traefik with Let's Encrypt for TLS)
deploy_ac          = true
acme_email         = "admin@layerv.xyz"
ac_auth_service_id = "layerv"
ac_resource_ids    = ["demo", "mini-app-demo"]

# Terraform state bucket for GitHub Actions permissions
terraform_state_bucket = "layerv-terraform-state-767397897469"
terraform_lock_table   = "terraform-state-lock"

# Security services
enable_cloudtrail = true

# NHP Server configuration
# Set to true for staging to enable debug features
dev_mode      = true
resource_mode = "api"
auth_url      = "http://127.0.0.1:8888" # Internal AC auth endpoint
# auth_signing_key and auth_aes_key are passed via GitHub Secrets (TF_VAR_auth_signing_key, TF_VAR_auth_aes_key)

# Slack notifications via AWS Chatbot
enable_slack_notifications = true
slack_workspace_id         = "T09UP622L90" # LayerV workspace
slack_channel_id           = "C09UP62A8F4" # #all-layerv

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
