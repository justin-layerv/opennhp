# Import blocks for existing manually-created traefik-plugins deploy resources.
# These resources were created outside Terraform and need to be imported into state.
# This file can be deleted after the first successful terraform apply.

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_iam_role.github_actions
  id = "traefik-plugins-sandbox-github-actions"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_iam_role_policy.github_actions
  id = "traefik-plugins-sandbox-github-actions:github-actions-policy"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_iam_role_policy.deploy
  id = "traefik-plugins-sandbox-github-actions:traefik-plugins-sandbox-deploy-policy"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_s3_bucket.deploy
  id = "traefik-plugins-deploy-767397897469"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_s3_bucket_versioning.deploy
  id = "traefik-plugins-deploy-767397897469"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_s3_bucket_server_side_encryption_configuration.deploy
  id = "traefik-plugins-deploy-767397897469"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_s3_bucket_public_access_block.deploy
  id = "traefik-plugins-deploy-767397897469"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_s3_bucket_lifecycle_configuration.deploy
  id = "traefik-plugins-deploy-767397897469"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_ssm_document.deploy
  id = "traefik-plugins-sandbox-deploy-plugin"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_ssm_document.rollback
  id = "traefik-plugins-sandbox-rollback-plugin"
}

import {
  to = module.nhp.module.traefik_plugins_deploy.aws_cloudwatch_log_group.deploy
  id = "/aws/ssm/traefik-plugins-sandbox"
}
