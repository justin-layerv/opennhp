# Clean fixture: every tag value sits inside AWS's allowed charset
# [A-Za-z0-9_.:/=+\-@\s]. Exercises every tag form the lint scans and
# the legitimate-pattern edge cases the rewrite must NOT false-positive
# on:
#   1. Literal `tags = { ... }`
#   2. `tags = merge(var.tags, { ... })`
#   3. `default_tags { tags = { ... } }` inside a provider block
#   4. ASG singular `tag { key = ... value = ... }` block
#   5. `locals { tag_map = { ... } }` whose member name contains `tag`
#   6. Single-line tag map on the opener line (no false negatives, but
#      also no false positives on clean single-line maps)
#   7. HCL whitespace escapes — `\n`, `\t`, `\r` are unescaped before
#      the charset check and resolve to chars in `\s` (allowed). The
#      lint must not false-positive on tag values that use them.
#      (Note: `\"` and `\\` resolve to chars OUTSIDE the AWS allowed
#      set, so a tag value containing them is a real violation, not
#      something the clean fixture should exercise.)
#   8. Nested-brace `${...}` interpolations — `${jsonencode({...})}`
#      stripped recursively so the leftover `)}` from a single-pass
#      strip does not surface as a false positive.
# Expected exit: 0.

variable "name_prefix" {
  type    = string
  default = "layerv"
}

variable "tags" {
  type    = map(string)
  default = {}
}

provider "aws" {
  region = "us-east-2"
  default_tags {
    tags = {
      Project     = "LayerV-NHP"
      Environment = "sandbox"
      ManagedBy   = "terraform"
    }
  }
}

resource "aws_dynamodb_table" "literal" {
  name         = "${var.name_prefix}-clean-literal"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name      = "${var.name_prefix}-clean-literal"
    Component = "dynamodb"
    Purpose   = "Clean fixture: ascii only"
  }
}

resource "aws_dynamodb_table" "merged" {
  name         = "${var.name_prefix}-clean-merged"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = merge(var.tags, {
    Name          = "${var.name_prefix}-clean-merged"
    Component     = "dynamodb"
    Purpose       = "Sidecar agent X25519 public-key registry: bootstrap to knock"
    "Owner Email" = "ops@example.com"
  })
}

resource "aws_s3_bucket" "single_line_clean" {
  bucket = "${var.name_prefix}-single-line-clean"
  tags   = { Name = "single-line-clean", Component = "s3" }
}

resource "aws_s3_bucket" "opener_line_kv_clean" {
  bucket = "${var.name_prefix}-opener-line-kv-clean"
  tags = merge(var.tags, { Component = "s3",
    Name = "opener-line-kv-clean"
  })
}

resource "aws_s3_bucket" "trailing_comment_clean" {
  bucket = "${var.name_prefix}-trailing-comment-clean"
  tags = {
    Name    = "trailing-comment-clean" # benign trailing comment
    Purpose = "explanatory only"       # another one
  }
}

resource "aws_autoscaling_group" "asg_singular_clean" {
  name                = "${var.name_prefix}-asg-clean"
  max_size            = 1
  min_size            = 0
  desired_capacity    = 1
  vpc_zone_identifier = ["subnet-deadbeef"]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-asg-clean"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "asg"
    propagate_at_launch = true
  }
}

# String-escape and nested-interpolation edge cases — must NOT false-positive.
resource "aws_s3_bucket" "escape_edge_cases" {
  bucket = "${var.name_prefix}-escape-edge"
  tags = {
    Name           = "escape-edge"
    HasNewline     = "line1\nline2"
    HasTab         = "col1\tcol2"
    HasCR          = "line1\rline2"
    HasInterpolate = "${jsonencode({ a = 1, b = 2 })}-suffix"
  }
}

# locals tag-map — scanned because the local's name contains "tag".
locals {
  common_tags = {
    Project   = "LayerV-NHP"
    ManagedBy = "terraform"
  }
}

# locals block whose members are NOT tag-related — scanner must skip.
# A literal `{ description = "(parens are fine here)" }` here should
# not trip the lint because `description` is not a tag value; this
# fixture catches over-eager `locals { ... }` scanning.
locals {
  description_block = {
    description = "(parens are fine in a description local)"
    notes       = "→ arrow is fine here too"
  }
}
