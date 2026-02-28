# Billing - IAM Roles and Policies
#
# One IAM role per Lambda function following least-privilege principle.
# Common: AWSLambdaBasicExecutionRole + AWSXRayDaemonWriteAccess
# Per-function: specific DynamoDB, Secrets Manager, SQS, SES, CloudWatch permissions

# ==============================================================================
# 1. Checkout Session IAM
# ==============================================================================

resource "aws_iam_role" "checkout_session" {
  name = "${var.name_prefix}-billing-checkout-session-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-checkout-session-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "checkout_session_basic" {
  role       = aws_iam_role.checkout_session.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "checkout_session_xray" {
  role       = aws_iam_role.checkout_session.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "checkout_session" {
  name = "${var.name_prefix}-billing-checkout-session-policy"
  role = aws_iam_role.checkout_session.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBCustomers"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = var.customers_table_arn
      },
      {
        Sid      = "SecretsManagerStripe"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.stripe_secret_arn
      }
    ]
  })
}

# ==============================================================================
# 2. Stripe Webhook IAM
# ==============================================================================

resource "aws_iam_role" "stripe_webhook" {
  name = "${var.name_prefix}-billing-stripe-webhook-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-stripe-webhook-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "stripe_webhook_basic" {
  role       = aws_iam_role.stripe_webhook.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "stripe_webhook_xray" {
  role       = aws_iam_role.stripe_webhook.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "stripe_webhook" {
  name = "${var.name_prefix}-billing-stripe-webhook-policy"
  role = aws_iam_role.stripe_webhook.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBCustomers"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Scan"
          ]
          Resource = var.customers_table_arn
        },
        {
          Sid    = "DynamoDBWebhookDedup"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem"
          ]
          Resource = aws_dynamodb_table.webhook_dedup.arn
        },
        {
          Sid      = "SecretsManagerWebhook"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = local.stripe_webhook_secret_arn
        },
        {
          Sid      = "SecretsManagerStripeAPI"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = local.stripe_secret_arn
        }
      ],
      var.sns_topic_arn != null ? [
        {
          Sid      = "SNSPublish"
          Effect   = "Allow"
          Action   = ["sns:Publish"]
          Resource = var.sns_topic_arn
        }
      ] : []
    )
  })
}

# ==============================================================================
# 3. Usage Reporter IAM
# ==============================================================================

resource "aws_iam_role" "usage_reporter" {
  name = "${var.name_prefix}-billing-usage-reporter-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-usage-reporter-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "usage_reporter_basic" {
  role       = aws_iam_role.usage_reporter.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "usage_reporter_xray" {
  role       = aws_iam_role.usage_reporter.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "usage_reporter" {
  name = "${var.name_prefix}-billing-usage-reporter-policy"
  role = aws_iam_role.usage_reporter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "SQSReceive"
          Effect = "Allow"
          Action = [
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes"
          ]
          Resource = aws_sqs_queue.usage_events.arn
        },
        {
          Sid    = "DynamoDBCustomers"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:UpdateItem"
          ]
          Resource = var.customers_table_arn
        },
        {
          Sid      = "SecretsManagerStripe"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = local.stripe_secret_arn
        }
      ],
      local.has_audit_table ? [
        {
          Sid    = "DynamoDBAudit"
          Effect = "Allow"
          Action = [
            "dynamodb:PutItem"
          ]
          Resource = var.billing_audit_table_arn
        }
      ] : [],
      var.sqs_kms_key_arn != null ? [
        {
          Sid    = "KMSDecryptSQS"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ]
          Resource = var.sqs_kms_key_arn
        }
      ] : []
    )
  })
}

# ==============================================================================
# 4. Reconciliation IAM
# ==============================================================================

resource "aws_iam_role" "reconciliation" {
  name = "${var.name_prefix}-billing-reconciliation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-reconciliation-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "reconciliation_basic" {
  role       = aws_iam_role.reconciliation.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "reconciliation_xray" {
  role       = aws_iam_role.reconciliation.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "reconciliation" {
  name = "${var.name_prefix}-billing-reconciliation-policy"
  role = aws_iam_role.reconciliation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBCustomers"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
            "dynamodb:Scan"
          ]
          Resource = var.customers_table_arn
        },
        {
          Sid      = "CloudWatchMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/Billing"
            }
          }
        }
      ],
      local.has_audit_table ? [
        {
          Sid    = "DynamoDBAudit"
          Effect = "Allow"
          Action = [
            "dynamodb:Query"
          ]
          Resource = var.billing_audit_table_arn
        }
      ] : []
    )
  })
}

# ==============================================================================
# 5. Payment Grace IAM
# ==============================================================================

resource "aws_iam_role" "payment_grace" {
  name = "${var.name_prefix}-billing-payment-grace-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-payment-grace-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "payment_grace_basic" {
  role       = aws_iam_role.payment_grace.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "payment_grace_xray" {
  role       = aws_iam_role.payment_grace.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "payment_grace" {
  name = "${var.name_prefix}-billing-payment-grace-policy"
  role = aws_iam_role.payment_grace.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBCustomers"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan"
        ]
        Resource = var.customers_table_arn
      },
      {
        Sid      = "SecretsManagerStripe"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.stripe_secret_arn
      },
      {
        Sid    = "SESEmail"
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "arn:aws:ses:${var.ses_region}:${data.aws_caller_identity.current.account_id}:identity/${var.from_email}"
      },
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/Billing"
          }
        }
      }
    ]
  })
}

# ==============================================================================
# 6. Invoices IAM
# ==============================================================================

resource "aws_iam_role" "invoices" {
  name = "${var.name_prefix}-billing-invoices-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-invoices-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "invoices_basic" {
  role       = aws_iam_role.invoices.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "invoices_xray" {
  role       = aws_iam_role.invoices.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "invoices" {
  name = "${var.name_prefix}-billing-invoices-policy"
  role = aws_iam_role.invoices.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBCustomers"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.customers_table_arn
      },
      {
        Sid      = "SecretsManagerStripe"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.stripe_secret_arn
      }
    ]
  })
}
