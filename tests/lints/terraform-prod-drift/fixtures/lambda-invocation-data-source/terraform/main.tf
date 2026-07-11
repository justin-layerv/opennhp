# Positive path for the refreshable Lambda invocation data source used to read
# live relay identity status. The provider Read calls lambda:InvokeFunction.

data "aws_lambda_invocation" "status" {
  function_name = "fixture-status"
  input         = jsonencode({ Action = "status" })
}
