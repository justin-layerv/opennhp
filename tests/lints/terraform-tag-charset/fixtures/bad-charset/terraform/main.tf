# Bad-charset fixture: each resource exercises one chars-outside-allowed
# regression class. The lint should report all violations and exit 1.
#
#   - unicode-arrow: U+2192 `→` (the original PR #1828 bug)
#   - ascii-arrow-and-parens: `(bootstrap -> knock)` — `>` and `(`/`)`
#     are all disallowed
#   - literal-form-bad-key: tag KEY contains parens (same charset rule
#     applies to keys)
#   - single-line-map: `tags = { K = "→" }` — opener and KV share a
#     line and the map closes on the same line
#   - opener-line-first-kv: first KV shares a line with the
#     `tags = merge(var.tags, {` opener
#   - trailing-comment: `KV # note` — value must still be checked
#   - asg-singular-tag: `tag { key=... value=... }` form used by
#     aws_autoscaling_group; offending tag-VALUE
#   - asg-singular-tag-key: same form, offending tag-KEY — annotation
#     must say "tag key contains…", not "tag value contains…"
#   - hash-in-string: `#` inside a double-quoted tag value; comment
#     stripping must respect string quoting
#   - locals-tag-map: `locals { *tag* = { ... } }` map literal whose
#     member name contains "tag" must be scanned
# Expected exit: 1.

variable "name_prefix" {
  type    = string
  default = "layerv"
}

variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_dynamodb_table" "unicode_arrow" {
  name         = "${var.name_prefix}-unicode-arrow"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-unicode-arrow"
    Purpose = "Sidecar agent X25519 public-key registry (bootstrap → knock)"
  })
}

resource "aws_dynamodb_table" "ascii_arrow_and_parens" {
  name         = "${var.name_prefix}-ascii-arrow-parens"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-ascii-arrow-parens"
    Purpose = "Sidecar agent X25519 public-key registry (bootstrap -> knock)"
  })
}

resource "aws_s3_bucket" "literal_form_bad_key" {
  bucket = "${var.name_prefix}-bad-key-fixture"

  tags = {
    Name           = "literal-form-bad-key"
    "Has (Parens)" = "value-is-fine"
  }
}

resource "aws_s3_bucket" "single_line_map" {
  bucket = "${var.name_prefix}-single-line-map"
  tags   = { Name = "single-line-map", Purpose = "bad arrow → here" }
}

resource "aws_s3_bucket" "opener_line_first_kv" {
  bucket = "${var.name_prefix}-opener-line-first-kv"
  tags = merge(var.tags, { Purpose = "bad → on opener line",
    Name = "opener-line-first-kv"
  })
}

resource "aws_s3_bucket" "trailing_comment" {
  bucket = "${var.name_prefix}-trailing-comment"
  tags = {
    Name    = "trailing-comment"
    Purpose = "bad → with comment" # explanatory note
  }
}

resource "aws_autoscaling_group" "asg_singular_tag" {
  name                = "${var.name_prefix}-asg-singular-tag"
  max_size            = 1
  min_size            = 0
  desired_capacity    = 1
  vpc_zone_identifier = ["subnet-deadbeef"]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-asg-singular-tag"
    propagate_at_launch = true
  }

  tag {
    key                 = "Purpose"
    value               = "ASG with bad → in value"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "asg_singular_tag_key" {
  name                = "${var.name_prefix}-asg-singular-tag-key"
  max_size            = 1
  min_size            = 0
  desired_capacity    = 1
  vpc_zone_identifier = ["subnet-deadbeef"]

  tag {
    key                 = "Bad>Key"
    value               = "value-is-fine"
    propagate_at_launch = true
  }
}

resource "aws_s3_bucket" "hash_in_string" {
  bucket = "${var.name_prefix}-hash-in-string"
  tags = {
    Name = "Ticket #1234"
  }
}

locals {
  agent_tags = {
    Name    = "locals-block-tags"
    Purpose = "locals → tag map"
  }
}
