# Canary Deployment Module - Outputs

output "state_machine_arn" {
  description = "Step Functions state machine ARN for canary deployment"
  value       = aws_sfn_state_machine.canary_deploy.arn
}

output "state_machine_name" {
  description = "Step Functions state machine name"
  value       = aws_sfn_state_machine.canary_deploy.name
}

output "composite_alarm_arn" {
  description = "CloudWatch composite alarm ARN for canary health"
  value       = aws_cloudwatch_composite_alarm.canary_health.arn
}

output "composite_alarm_name" {
  description = "CloudWatch composite alarm name for canary health"
  value       = aws_cloudwatch_composite_alarm.canary_health.alarm_name
}

output "lambda_function_arn" {
  description = "Canary orchestrator Lambda function ARN"
  value       = aws_lambda_function.orchestrator.arn
}

output "lambda_function_name" {
  description = "Canary orchestrator Lambda function name"
  value       = aws_lambda_function.orchestrator.function_name
}

output "ssm_canary_state_parameter" {
  description = "SSM parameter name for canary deployment state"
  value       = aws_ssm_parameter.canary_state.name
}
