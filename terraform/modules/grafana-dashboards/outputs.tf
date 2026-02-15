# Grafana Dashboards Module Outputs

output "folder_uid" {
  description = "Grafana folder UID for QURL dashboards"
  value       = var.create_dashboards ? grafana_folder.qurl[0].uid : null
}

output "folder_url" {
  description = "URL to the QURL dashboards folder"
  value       = var.create_dashboards ? "${var.grafana_url}/dashboards/f/${grafana_folder.qurl[0].uid}" : null
}

output "operations_dashboard_url" {
  description = "URL to the QURL Operations dashboard"
  value       = var.create_dashboards ? "${var.grafana_url}/d/${grafana_dashboard.operations[0].uid}" : null
}

output "business_dashboard_url" {
  description = "URL to the QURL Business dashboard"
  value       = var.create_dashboards ? "${var.grafana_url}/d/${grafana_dashboard.business[0].uid}" : null
}

output "nhp_infrastructure_dashboard_url" {
  description = "URL to the NHP Infrastructure dashboard (null if CloudWatch datasource not enabled)"
  value       = var.create_dashboards && var.cloudwatch_datasource_enabled ? "${var.grafana_url}/d/${grafana_dashboard.nhp_infrastructure[0].uid}" : null
}

output "grafana_cloudwatch_role_arn" {
  description = "IAM role ARN for Grafana Cloud CloudWatch access (null if not created)"
  value       = local.create_cw_role ? aws_iam_role.grafana_cloudwatch[0].arn : null
}

output "aws_cost_dashboard_url" {
  description = "URL to the AWS Cost dashboard (null if Athena datasource not enabled)"
  value       = var.create_dashboards && var.athena_datasource_enabled ? "${var.grafana_url}/d/${grafana_dashboard.aws_cost[0].uid}" : null
}

output "nhp_logs_dashboard_url" {
  description = "URL to the NHP Logs dashboard (null if CloudWatch datasource not enabled)"
  value       = var.create_dashboards && var.cloudwatch_datasource_enabled ? "${var.grafana_url}/d/${grafana_dashboard.nhp_logs[0].uid}" : null
}
