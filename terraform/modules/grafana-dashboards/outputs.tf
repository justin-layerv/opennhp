# Grafana Dashboards Module Outputs

output "folder_uid" {
  description = "Grafana folder UID for QURL dashboards"
  value       = grafana_folder.qurl.uid
}

output "folder_url" {
  description = "URL to the QURL dashboards folder"
  value       = "${var.grafana_url}/dashboards/f/${grafana_folder.qurl.uid}"
}

output "operations_dashboard_url" {
  description = "URL to the QURL Operations dashboard"
  value       = "${var.grafana_url}/d/${grafana_dashboard.operations.uid}"
}

output "business_dashboard_url" {
  description = "URL to the QURL Business dashboard"
  value       = "${var.grafana_url}/d/${grafana_dashboard.business.uid}"
}

output "nhp_infrastructure_dashboard_url" {
  description = "URL to the NHP Infrastructure dashboard (null if CloudWatch datasource not enabled)"
  value       = var.cloudwatch_datasource_enabled ? "${var.grafana_url}/d/${grafana_dashboard.nhp_infrastructure[0].uid}" : null
}

output "grafana_cloudwatch_role_arn" {
  description = "IAM role ARN for Grafana Cloud CloudWatch access (null if not created)"
  value       = local.create_cw_role ? aws_iam_role.grafana_cloudwatch[0].arn : null
}

output "aws_cost_dashboard_url" {
  description = "URL to the AWS Cost dashboard (null if Athena datasource not enabled)"
  value       = var.athena_datasource_enabled ? "${var.grafana_url}/d/${grafana_dashboard.aws_cost[0].uid}" : null
}
