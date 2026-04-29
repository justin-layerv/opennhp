# SSM Parameters for QURL FRP Server
# Only parameters that an out-of-band actor (CI/CD, ops) needs to discover
# or update at runtime live here. Static config (ports, subdomain host) is
# baked into user_data.sh.tpl at plan time via templatefile() — keeping
# duplicate copies in SSM risks them diverging from the rendered script.

resource "aws_ssm_parameter" "image_tag" {
  name        = "/${var.environment}/nhp/frps/image-tag"
  description = "QURL FRP server binary version tag. Read by user_data at boot; CI/CD updates it between releases without a Terraform apply."
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-image-tag"
    Component = "frps"
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "asg_name" {
  name        = "/${var.environment}/nhp/frps/asg-name"
  description = "QURL FRP server Auto Scaling Group name - used by CI/CD for instance refresh after an image_tag update."
  type        = "String"
  value       = aws_autoscaling_group.frps.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-asg-name"
    Component = "frps"
  })
}
