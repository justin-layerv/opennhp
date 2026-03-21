output "echo_url" {
  description = "HTTPS URL of the echo server Lambda function URL"
  value       = aws_lambda_function_url.echo.function_url
}

output "function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.echo.function_name
}
