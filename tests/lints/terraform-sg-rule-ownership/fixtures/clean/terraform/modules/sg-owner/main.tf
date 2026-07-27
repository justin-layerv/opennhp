# Class 1 — no inline rule attributes at all. Nothing is authoritative, so
# the standalone rules below are sole owners. This is the shape #3281 moved
# the Redis SG to.
resource "aws_security_group" "clean_no_inline" {
  name_prefix = "clean-no-inline-"
  vpc_id      = "vpc-clean"
  description = "Clean fixture: rules owned entirely by standalone resources"

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [ingress, egress]
  }
}

resource "aws_vpc_security_group_ingress_rule" "clean_no_inline_https" {
  security_group_id = aws_security_group.clean_no_inline.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "clean-no-inline: HTTPS from VPC"
}

# Class 2 — inline `egress = []` retained but frozen via ignore_changes, so
# the standalone egress rule is the sole effective owner.
resource "aws_security_group" "clean_frozen_egress" {
  name_prefix = "clean-frozen-egress-"
  vpc_id      = "vpc-clean"
  description = "Clean fixture: inline egress frozen by ignore_changes"

  egress = []

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [description, ingress, egress]
  }
}

resource "aws_vpc_security_group_egress_rule" "clean_frozen_egress_out" {
  security_group_id = aws_security_group.clean_frozen_egress.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "clean-frozen-egress: HTTPS to VPC"
}

# Class 3 — inline `ingress` block with standalone *egress* rules only.
# Different attribute, no conflict. A direction-blind lint flags this.
resource "aws_security_group" "clean_direction_split" {
  name_prefix = "clean-direction-split-"
  vpc_id      = "vpc-clean"
  description = "Clean fixture: inline ingress, standalone egress only"

  ingress {
    from_port   = 62206
    to_port     = 62206
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "clean-direction-split: NHP UDP from VPC"
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [egress]
  }
}

resource "aws_vpc_security_group_egress_rule" "clean_direction_split_dns" {
  security_group_id = aws_security_group.clean_direction_split.id
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "clean-direction-split: DNS egress"
}

# Class 4 — count-indexed reference. The resolver must strip the `[0]`.
resource "aws_security_group" "clean_counted" {
  count       = 1
  name_prefix = "clean-counted-"
  vpc_id      = "vpc-clean"
  description = "Clean fixture: count-indexed SG with standalone rules"

  lifecycle {
    ignore_changes = [ingress, egress]
  }
}

resource "aws_vpc_security_group_ingress_rule" "clean_counted_udp" {
  security_group_id = aws_security_group.clean_counted[0].id
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "clean-counted: NHP UDP ingress"
}

# Class 5 — the cross-module target. Declares no inline rules, so the rule
# attached from the sibling module is unopposed.
resource "aws_security_group" "clean_cross_module" {
  name_prefix = "clean-cross-module-"
  vpc_id      = "vpc-clean"
  description = "Clean fixture: cross-module target with no inline rules"

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [ingress, egress]
  }
}
