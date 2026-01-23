# Grafana Dashboards Module Variables
#
# NOTE: This module expects a grafana provider to be passed from the caller.
# The provider configuration (url, auth) should be defined in the root module.

variable "grafana_url" {
  description = "Grafana Cloud URL (for generating dashboard URLs in outputs)"
  type        = string
}

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "prometheus_datasource_uid" {
  description = "UID of the Prometheus/Mimir datasource in Grafana Cloud (find in Connections > Data sources)"
  type        = string
  default     = "grafanacloud-prom"
}

variable "tempo_datasource_uid" {
  description = "UID of the Tempo datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-traces"
}

variable "loki_datasource_uid" {
  description = "UID of the Loki datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-logs"
}

variable "folder_name" {
  description = "Grafana folder name for QURL dashboards"
  type        = string
  default     = "QURL"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
