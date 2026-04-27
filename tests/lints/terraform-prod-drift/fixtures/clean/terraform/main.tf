# Clean fixture: a data source paired with the matching IAM grant on the
# canonical github_actions role (declared under modules/ecr/, mirroring
# the real terraform tree). Both lints expect exit 0.
#
# `deploy_website_api_dns` defaults to true so both the data source AND
# the matching grant instantiate — exercises the fully-on path. The lint
# itself is gating-blind (takes the union of policies regardless of
# `count`), so the value of this variable doesn't change the lint's
# verdict, but a future reader expecting "clean" to mean "everything is
# turned on and consistent" gets that.

data "aws_cloudformation_stack" "website_api" {
  count = var.deploy_website_api_dns ? 1 : 0
  name  = "fixture-stack"
}

variable "deploy_website_api_dns" {
  type    = bool
  default = true
}
