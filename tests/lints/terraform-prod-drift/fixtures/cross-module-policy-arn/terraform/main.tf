# cross-module-policy-arn fixture (cr round 13 coverage gap):
#
# Regression fence for the third `policy_arn` shape: a cross-module
# module-output reference (`module.shared.write_policy_arn`).
# Pre-fix, this fell through both `customer_managed_re` and
# `external_arn_re` and triggered the misleading "policy_arn the lint
# can't recognize" warn — implying a typo when the source was
# legitimate. Post-fix, the lint emits a specific warn that explains
# the limitation (lint doesn't walk module outputs) and the
# resolution path.
#
# The data source has no required actions so the IAM coverage check
# exits 0; only the warn shape is under test.

data "aws_caller_identity" "current" {}

module "ecr" {
  source = "./modules/ecr"
}

module "shared" {
  source = "./modules/shared"
}

resource "aws_iam_role_policy_attachment" "shared_write" {
  role       = module.ecr.github_actions_role_name
  policy_arn = module.shared.write_policy_arn
}
