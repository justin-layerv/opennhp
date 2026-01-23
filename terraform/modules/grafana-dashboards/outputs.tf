# Grafana Dashboards Module Outputs

output "folder_id" {
  description = "Grafana folder ID for QURL dashboards"
  value       = grafana_folder.qurl.id
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
