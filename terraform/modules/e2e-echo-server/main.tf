# E2E Test Echo Server
# A lightweight Lambda function URL that serves as the target backend
# for QURL E2E tests. Returns request metadata as JSON so tests can
# verify traffic actually flowed through the NHP/QURL system.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

# Explicit log group with short retention to avoid unbounded log accumulation
resource "aws_cloudwatch_log_group" "echo" {
  name              = "/aws/lambda/${var.name_prefix}-e2e-echo"
  retention_in_days = 7

  tags = var.tags
}

data "archive_file" "echo_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/index.mjs"
  output_path = "${path.module}/lambda/echo.zip"
}

resource "aws_lambda_function" "echo" {
  depends_on = [aws_cloudwatch_log_group.echo]

  function_name    = "${var.name_prefix}-e2e-echo"
  filename         = data.archive_file.echo_lambda.output_path
  source_code_hash = data.archive_file.echo_lambda.output_base64sha256
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  timeout          = 10
  memory_size      = 128

  role = aws_iam_role.echo_lambda.arn

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  tags = var.tags
}

resource "aws_lambda_function_url" "echo" {
  function_name      = aws_lambda_function.echo.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["*"]
    max_age       = 3600
  }
}

# IAM role for Lambda execution
resource "aws_iam_role" "echo_lambda" {
  name = "${var.name_prefix}-e2e-echo-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "echo_lambda_basic" {
  role       = aws_iam_role.echo_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Store the echo URL in SSM so E2E tests can discover it
resource "aws_ssm_parameter" "echo_url" {
  name        = "/${var.name_prefix}/e2e/echo-url"
  description = "E2E echo server Lambda function URL for test discovery"
  type        = "String"
  value       = aws_lambda_function_url.echo.function_url

  tags = var.tags
}
