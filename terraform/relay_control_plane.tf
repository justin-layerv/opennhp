# Stable relay control plane. Identity, image pin, certificate, and public DNS
# outlive the environment's single disposable relay fleet. The current sandbox
# fleet can therefore be replaced by the DMZ fleet without rotating identity or
# recreating certificate and DNS ownership.

module "relay_identity" {
  count  = var.deploy_relay ? 1 : 0
  source = "./modules/relay-identity"

  environment              = var.environment
  name_prefix              = local.name_prefix
  secrets_kms_key_arn      = module.kms.secrets_key_arn
  iam_propagation_duration = local.iam_propagation_duration
  tags                     = merge(local.common_tags, { Service = "nhp-relay" })
}

resource "aws_ssm_parameter" "relay_image_tag" {
  count = var.deploy_relay ? 1 : 0

  name        = "/${var.environment}/nhp/relay/image-tag"
  description = "NHP Relay Docker image tag — updated by CI/CD"
  type        = "String"
  value       = var.image_tag

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ssm-relay-image-tag"
    Component = "relay"
    Service   = "nhp-relay"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# Single authoritative deploy target. CI continues reading the established
# /<environment>/nhp/relay/asg-name path; only Terraform ownership moves out of
# the disposable fleet. Replacing the sandbox fleet updates this value in place.
# CI never writes this parameter, so Terraform remains authoritative and this
# resource intentionally does not ignore value changes like relay_image_tag.
resource "aws_ssm_parameter" "relay_asg_name" {
  count = var.deploy_relay ? 1 : 0

  name        = "/${var.environment}/nhp/relay/asg-name"
  description = "NHP Relay Auto Scaling Group name — used by CI/CD for instance refresh"
  type        = "String"
  value       = one(module.relay[*].asg_name)

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ssm-relay-asg-name"
    Component = "relay"
    Service   = "nhp-relay"
  })
}

locals {
  relay_current_public_key_b64 = var.deploy_relay ? one(module.relay_identity[*].relay_public_key_b64) : ""

  # Canonical ordering makes a current/additional role swap during promotion
  # byte-identical while both public keys remain trusted.
  relay_trusted_public_keys_b64 = var.deploy_relay ? sort(distinct(concat(
    [local.relay_current_public_key_b64],
    var.relay_additional_trusted_public_keys_b64,
  ))) : []

  relay_effective_certificate_arn = !var.deploy_relay ? "" : (
    var.relay_provision_certificate
    ? one(aws_acm_certificate_validation.relay[*].certificate_arn)
    : var.relay_existing_certificate_arn
  )
}

resource "terraform_data" "relay_control_plane_preconditions" {
  count = var.deploy_relay ? 1 : 0

  lifecycle {
    precondition {
      condition     = !contains(var.relay_additional_trusted_public_keys_b64, local.relay_current_public_key_b64)
      error_message = "relay_additional_trusted_public_keys_b64 must not contain the current identity key. During rotation, swap current/additional roles after promotion instead of leaving a duplicate."
    }

    precondition {
      # The moved block below must use a static address, so it cannot reference
      # var.relay_dns_name. Fail the sandbox plan if its for_each key drifts
      # before the one-time ownership move is applied and retired (#3145).
      condition     = var.environment != "sandbox" || var.relay_dns_name == "relay.qurl.link.layerv.xyz"
      error_message = "sandbox relay_dns_name must remain relay.qurl.link.layerv.xyz until the relay certificate-validation moved block is applied and retired (#3145)."
    }
  }
}

# Resolve the same-account zone only when certificate validation or alias
# management needs it. Prod remains a count-zero, operator-managed path.
data "aws_route53_zone" "relay_selected" {
  count = var.deploy_relay && (var.relay_provision_certificate || var.relay_manage_dns_alias) ? 1 : 0

  zone_id = var.relay_route53_zone_id

  lifecycle {
    precondition {
      condition     = var.relay_route53_zone_id != ""
      error_message = "relay certificate provisioning or alias management requires relay_route53_zone_id."
    }
  }
}

resource "time_sleep" "relay_route53_record_change_iam_propagation" {
  count = var.deploy_relay && (var.relay_provision_certificate || var.relay_manage_dns_alias) && length(local.route53_record_change_iam_propagation_triggers) > 0 ? 1 : 0

  triggers        = local.route53_record_change_iam_propagation_triggers
  create_duration = local.iam_propagation_duration
}

resource "aws_acm_certificate" "relay" {
  count = var.deploy_relay && var.relay_provision_certificate ? 1 : 0

  domain_name       = var.relay_dns_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = var.relay_route53_zone_id != ""
      error_message = "relay_provision_certificate=true requires relay_route53_zone_id."
    }

    precondition {
      condition = (
        var.relay_dns_name == trimsuffix(data.aws_route53_zone.relay_selected[0].name, ".") ||
        endswith(var.relay_dns_name, ".${trimsuffix(data.aws_route53_zone.relay_selected[0].name, ".")}")
      )
      error_message = "relay_dns_name must be the apex of, or a subdomain of, relay_route53_zone_id."
    }

    postcondition {
      condition     = length(self.domain_validation_options) == 1
      error_message = "The relay certificate owner assumes exactly one domain validation option."
    }
  }

  tags = merge(local.common_tags, {
    Component = "relay"
    Service   = "nhp-relay"
  })
}

locals {
  relay_cert_dvo = var.deploy_relay && var.relay_provision_certificate ? tolist(aws_acm_certificate.relay[0].domain_validation_options)[0] : null
}

resource "aws_route53_record" "relay_cert_validation" {
  for_each = var.deploy_relay && var.relay_provision_certificate ? toset([var.relay_dns_name]) : toset([])

  zone_id         = var.relay_route53_zone_id
  name            = local.relay_cert_dvo.resource_record_name
  type            = local.relay_cert_dvo.resource_record_type
  ttl             = 300
  records         = [local.relay_cert_dvo.resource_record_value]
  allow_overwrite = true

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [time_sleep.relay_route53_record_change_iam_propagation]
}

resource "aws_acm_certificate_validation" "relay" {
  count = var.deploy_relay && var.relay_provision_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.relay[0].arn
  validation_record_fqdns = [for record in aws_route53_record.relay_cert_validation : record.fqdn]
}

resource "aws_route53_record" "relay_alias" {
  count = var.deploy_relay && var.relay_manage_dns_alias ? 1 : 0

  zone_id = var.relay_route53_zone_id
  name    = var.relay_dns_name
  type    = "A"

  alias {
    name                   = one(module.relay[*].alb_dns_name)
    zone_id                = one(module.relay[*].alb_zone_id)
    evaluate_target_health = false
  }

  lifecycle {
    precondition {
      condition     = var.relay_route53_zone_id != ""
      error_message = "relay_manage_dns_alias=true requires relay_route53_zone_id."
    }

    precondition {
      condition = (
        var.relay_dns_name == trimsuffix(data.aws_route53_zone.relay_selected[0].name, ".") ||
        endswith(var.relay_dns_name, ".${trimsuffix(data.aws_route53_zone.relay_selected[0].name, ".")}")
      )
      error_message = "relay_dns_name must be the apex of, or a subdomain of, relay_route53_zone_id."
    }
  }

  depends_on = [
    terraform_data.relay_control_plane_preconditions,
    time_sleep.relay_route53_record_change_iam_propagation,
  ]
}

# Ownership-only moves. Remote names and IDs remain unchanged.
moved {
  from = module.relay[0].aws_iam_role.keygen_lambda
  to   = module.relay_identity[0].aws_iam_role.keygen_lambda
}

moved {
  from = module.relay[0].aws_iam_role_policy_attachment.keygen_lambda_basic
  to   = module.relay_identity[0].aws_iam_role_policy_attachment.keygen_lambda_basic
}

moved {
  from = module.relay[0].aws_iam_role_policy.keygen_lambda_secrets
  to   = module.relay_identity[0].aws_iam_role_policy.keygen_lambda_secrets
}

moved {
  from = module.relay[0].aws_lambda_function.keygen
  to   = module.relay_identity[0].aws_lambda_function.keygen
}

moved {
  from = module.relay[0].aws_secretsmanager_secret.relay
  to   = module.relay_identity[0].aws_secretsmanager_secret.relay
}

moved {
  from = module.relay[0].aws_lambda_invocation.keygen
  to   = module.relay_identity[0].aws_lambda_invocation.keygen
}

moved {
  from = module.relay[0].aws_ssm_parameter.image_tag
  to   = aws_ssm_parameter.relay_image_tag[0]
}

moved {
  from = module.relay[0].aws_ssm_parameter.asg_name
  to   = aws_ssm_parameter.relay_asg_name[0]
}

moved {
  from = module.relay[0].time_sleep.route53_record_change_iam_propagation[0]
  to   = time_sleep.relay_route53_record_change_iam_propagation[0]
}

moved {
  from = module.relay[0].aws_acm_certificate.relay[0]
  to   = aws_acm_certificate.relay[0]
}

moved {
  # Pinned to the sandbox tfvars key at migration time. Do not change
  # relay_dns_name until this move has been applied and retired everywhere.
  from = module.relay[0].aws_route53_record.cert_validation["relay.qurl.link.layerv.xyz"]
  to   = aws_route53_record.relay_cert_validation["relay.qurl.link.layerv.xyz"]
}

moved {
  from = module.relay[0].aws_acm_certificate_validation.relay[0]
  to   = aws_acm_certificate_validation.relay[0]
}

moved {
  from = module.relay[0].aws_route53_record.alb_alias[0]
  to   = aws_route53_record.relay_alias[0]
}
