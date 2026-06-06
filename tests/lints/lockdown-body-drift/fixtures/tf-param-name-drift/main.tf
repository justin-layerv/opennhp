# Fixture for scripts/check-lockdown-body-drift.sh. NOT real Terraform — only
# the patterns the lint greps for are load-bearing; this is never applied.
locals {
  public_internal_lockdown_body = jsonencode({ error = "not found" })
}

resource "aws_lb_listener_rule" "public_internal_block" {
  count = var.domain_name != null && var.internal_alb_enabled ? 1 : 0
  action {
    fixed_response {
      content_type = "application/json"
      message_body = local.public_internal_lockdown_body
      status_code  = "404"
    }
  }
}

resource "aws_ssm_parameter" "public_internal_lockdown_body" {
  count = var.domain_name != null && var.internal_alb_enabled ? 1 : 0
  name  = "/${var.environment}/nhp/qurl/renamed-body"
  value = local.public_internal_lockdown_body
}
