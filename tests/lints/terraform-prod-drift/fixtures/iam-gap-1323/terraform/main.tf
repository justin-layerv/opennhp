# Reproduces #1323: a `data "aws_cloudformation_stack"` block was added
# without granting `cloudformation:DescribeStacks` + `cloudformation:GetTemplate`
# to the github_actions role. The IAM coverage lint must flag this.

data "aws_cloudformation_stack" "website_api" {
  count = var.deploy_website_api_dns ? 1 : 0
  name  = "fixture-stack"
}

variable "deploy_website_api_dns" {
  type    = bool
  default = true
}
