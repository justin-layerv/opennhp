# Temporary import blocks to reconcile state after incident.
# Remove after successful apply.

import {
  to = module.auth0.aws_secretsmanager_secret.dev_portal_mgmt[0]
  id = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/developer-portal/auth0-mgmt-RUh8oi"
}

import {
  to = module.auth0.aws_secretsmanager_secret_version.dev_portal_mgmt[0]
  id = "arn:aws:secretsmanager:us-east-2:235500187906:secret:layerv-nhp-prod/developer-portal/auth0-mgmt-RUh8oi|terraform-20260228072421498100000003"
}
