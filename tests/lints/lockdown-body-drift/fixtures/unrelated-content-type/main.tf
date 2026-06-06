# An unrelated resource with its own content_type. check 6 is block-scoped to
# the lockdown rule, so this must NOT trip it (regression guard for the
# file-wide foot-gun cr flagged on PR #2374).
resource "aws_s3_object" "unrelated" {
  content_type = "text/html"
}

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
  name  = "/${var.environment}/nhp/qurl/internal-lockdown-body"
  value = local.public_internal_lockdown_body
}
