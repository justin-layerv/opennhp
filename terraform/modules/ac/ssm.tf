# SSM Documents and State Manager Associations for AC instances
# Provides automated maintenance: log rotation, disk monitoring, bootstrap

# ==================== Bootstrap Instance ====================
# Ensures SSM agent and AWS CLI are installed

resource "aws_ssm_document" "bootstrap_instance" {
  count = var.enable_ssm_maintenance ? 1 : 0

  name            = "${var.name_prefix}-ac-bootstrap"
  document_type   = "Command"
  document_format = "YAML"

  content = <<-DOC
    schemaVersion: '2.2'
    description: 'Bootstrap AC instance with SSM agent and AWS CLI'
    mainSteps:
      - action: aws:runShellScript
        name: bootstrapInstance
        inputs:
          runCommand:
            - |
              ${indent(14, file("${path.module}/scripts/bootstrap-instance.sh"))}
  DOC

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-bootstrap"
  })
}

resource "aws_ssm_association" "bootstrap_instance" {
  count = var.enable_ssm_maintenance ? 1 : 0

  name             = aws_ssm_document.bootstrap_instance[0].name
  association_name = "${var.name_prefix}-ac-bootstrap"

  targets {
    key    = "tag:Name"
    values = [var.ac_instance_tag]
  }

  schedule_expression = "rate(1 day)"
  compliance_severity = "HIGH"
}

# ==================== Log Rotation ====================
# Daily cleanup of logs and journal to prevent disk filling

resource "aws_ssm_document" "log_rotation" {
  count = var.enable_ssm_maintenance ? 1 : 0

  name            = "${var.name_prefix}-ac-log-rotation"
  document_type   = "Command"
  document_format = "YAML"

  content = <<-DOC
    schemaVersion: '2.2'
    description: 'Manage log rotation and disk space on AC instances'
    parameters:
      JournalMaxSizeMB:
        type: String
        default: "${var.journal_max_size_mb}"
        description: "Maximum size for systemd journal in MB"
      LogRetentionDays:
        type: String
        default: "${var.log_retention_days}"
        description: "Days to retain rotated logs"
      NhpAcLogsPath:
        type: String
        default: "/home/ubuntu/nhp-ac/logs"
        description: "Path to NHP AC logs"
    mainSteps:
      - action: aws:runShellScript
        name: logRotation
        inputs:
          runCommand:
            - |
              #!/bin/bash
              set -e
              export JOURNAL_MAX_SIZE_MB="{{ JournalMaxSizeMB }}"
              export LOG_RETENTION_DAYS="{{ LogRetentionDays }}"
              export NHP_AC_LOGS_PATH="{{ NhpAcLogsPath }}"
              ${indent(14, file("${path.module}/scripts/log-rotation.sh"))}
  DOC

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-log-rotation"
  })
}

resource "aws_ssm_association" "log_rotation" {
  count = var.enable_ssm_maintenance ? 1 : 0

  name             = aws_ssm_document.log_rotation[0].name
  association_name = "${var.name_prefix}-ac-log-rotation"

  targets {
    key    = "tag:Name"
    values = [var.ac_instance_tag]
  }

  schedule_expression = var.log_rotation_schedule
  compliance_severity = "MEDIUM"

  parameters = {
    JournalMaxSizeMB = tostring(var.journal_max_size_mb)
    LogRetentionDays = tostring(var.log_retention_days)
    NhpAcLogsPath    = "/home/ubuntu/nhp-ac/logs"
  }
}

# ==================== Disk Monitoring ====================
# Publishes disk usage metrics to CloudWatch

resource "aws_ssm_document" "disk_monitor" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  name            = "${var.name_prefix}-ac-disk-monitor"
  document_type   = "Command"
  document_format = "YAML"

  content = <<-DOC
    schemaVersion: '2.2'
    description: 'Monitor disk space and publish CloudWatch metrics'
    parameters:
      Threshold:
        type: String
        default: "${var.disk_usage_threshold_percent}"
        description: "Disk usage threshold percentage for warnings"
    mainSteps:
      - action: aws:runShellScript
        name: diskMonitor
        inputs:
          runCommand:
            - |
              ${indent(14, file("${path.module}/scripts/disk-monitor.sh"))}
  DOC

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-disk-monitor"
  })
}

resource "aws_ssm_association" "disk_monitor" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  name             = aws_ssm_document.disk_monitor[0].name
  association_name = "${var.name_prefix}-ac-disk-monitor"

  targets {
    key    = "tag:Name"
    values = [var.ac_instance_tag]
  }

  # Run every 30 minutes (minimum for SSM associations)
  schedule_expression = "rate(30 minutes)"
  compliance_severity = "HIGH"

  parameters = {
    Threshold = tostring(var.disk_usage_threshold_percent)
  }
}

# ==================== CloudWatch Log Group for SSM ====================

resource "aws_cloudwatch_log_group" "ssm_output" {
  count = var.enable_ssm_maintenance ? 1 : 0

  name              = "/aws/ssm/${var.name_prefix}-ac"
  retention_in_days = 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-ssm-logs"
  })
}
