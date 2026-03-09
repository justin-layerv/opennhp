# ==============================================================================
# One-time imports: Auth0 tenant resources migrating from sandbox to prod
# ==============================================================================
# These Auth0 resources are tenant-level singletons shared by both environments.
# Previously managed by sandbox Terraform; now owned by prod.
# Remove these import blocks after the first successful prod terraform apply.
#
# AWS IAM user and policy already exist in the prod account (created previously).
# A NEW access key will be created by Terraform (old key's secret is lost),
# and the Auth0 email provider will be configured with the new credentials.
#
# POST-MIGRATION CLEANUP (see #726):
# 1. Delete this file after successful prod terraform apply
# 2. Remove "Migrate Auth0 tenant resources to prod" step from build-and-push.yml
# 3. Deactivate/delete the old IAM access key (AKIATNVHHWEBBE436Z5D) from prod account

# --- Auth0 tenant resources ---

import {
  to = module.auth0.auth0_role.user[0]
  id = "rol_6auarZE3p5HOGKha"
}

import {
  to = module.auth0.auth0_role_permissions.user[0]
  id = "rol_6auarZE3p5HOGKha"
}

import {
  to = module.auth0.auth0_action.default_permissions[0]
  id = "6bab272c-8082-4ed7-8fa3-55cace7a4e11"
}

import {
  to = module.auth0.auth0_trigger_actions.post_login[0]
  id = "post-login"
}

import {
  to = module.auth0.auth0_branding.layerv[0]
  id = "branding"
}

import {
  to = module.auth0.auth0_branding_theme.layerv[0]
  id = "mnP55Zqc6nN9StDsSZKAjKvDnoOkLz7c"
}

import {
  to = module.auth0.auth0_attack_protection.protection[0]
  id = "attack-protection"
}

import {
  to = module.auth0.auth0_email_provider.ses[0]
  id = "ses"
}

import {
  to = module.auth0.auth0_email_template.verify_email[0]
  id = "verify_email"
}

import {
  to = module.auth0.auth0_email_template.welcome_email[0]
  id = "welcome_email"
}

import {
  to = module.auth0.auth0_email_template.reset_email[0]
  id = "reset_email"
}

# --- AWS IAM resources (prod account) ---

import {
  to = module.auth0.aws_iam_user.auth0_ses[0]
  id = "layerv-nhp-prod-auth0-ses"
}

import {
  to = module.auth0.aws_iam_user_policy.auth0_ses_send[0]
  id = "layerv-nhp-prod-auth0-ses:ses-send-email"
}

# NOTE: aws_iam_access_key is intentionally NOT imported.
# The old key's secret_access_key is lost. Terraform will create a new key
# and configure the Auth0 email provider with the new credentials.
