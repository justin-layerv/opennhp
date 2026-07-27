# Violating fixture for check-terraform-sg-rule-ownership.py. One distinct
# regression class per security group, each with a unique resource name the
# annotation echoes so run-fixtures.sh can assert every class independently.
# Expected exit: 1.

# Class A — same-module mixing. Inline `ingress` is authoritative for the
# whole ingress set and revokes the standalone ingress rule below.
resource "aws_security_group" "bad_same_module_ingress" {
  name_prefix = "bad-same-module-ingress-"
  vpc_id      = "vpc-bad"
  description = "Violating fixture: inline ingress + standalone ingress rule"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "bad-same-module-ingress: HTTPS from VPC"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "bad_same_module_extra" {
  security_group_id = aws_security_group.bad_same_module_ingress.id
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "bad-same-module-ingress: plugin port, silently revoked"
}

# Class B — the #3281 shape exactly: this SG's id is exported and a rule in
# a different module attaches to it through a variable, while the inline
# `ingress` block here stays authoritative.
resource "aws_security_group" "bad_cross_module_redis" {
  name_prefix = "bad-cross-module-redis-"
  vpc_id      = "vpc-bad"
  description = "Violating fixture: cross-module standalone rule vs inline ingress"

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "bad-cross-module-redis: Redis from VPC"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Class C — inline `egress = []` with NO ignore_changes. The empty list is
# still a declaration, so the SG revokes the standalone egress rule.
resource "aws_security_group" "bad_unfrozen_egress" {
  name_prefix = "bad-unfrozen-egress-"
  vpc_id      = "vpc-bad"
  description = "Violating fixture: egress = [] without ignore_changes"

  egress = []

  lifecycle {
    create_before_destroy = true
    # Only `description` is frozen — `egress` is left authoritative.
    ignore_changes = [description]
  }
}

resource "aws_vpc_security_group_egress_rule" "bad_unfrozen_egress_out" {
  security_group_id = aws_security_group.bad_unfrozen_egress.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/16"
  description       = "bad-unfrozen-egress: HTTPS out, silently revoked"
}
