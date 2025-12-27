# RDS Aurora PostgreSQL Serverless v2 Module
# Provides managed PostgreSQL for the console application

# ==================== Random Password ====================

resource "random_password" "master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ==================== Secrets Manager ====================

resource "aws_secretsmanager_secret" "rds" {
  name        = "${var.name_prefix}-rds-credentials"
  description = "NHP ${var.environment} Aurora PostgreSQL credentials"
  kms_key_id  = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rds-credentials"
    Component = "rds"
  })
}

resource "aws_secretsmanager_secret_version" "rds" {
  secret_id = aws_secretsmanager_secret.rds.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.master.result
    dbname   = var.database_name
    engine   = "postgres"
    host     = aws_rds_cluster.main.endpoint
    port     = aws_rds_cluster.main.port
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ==================== Security Group ====================

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-rds"
  description = "Security group for NHP Aurora PostgreSQL"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-rds"
    Component = "rds"
  })
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_vpc" {
  security_group_id = aws_security_group.rds.id
  description       = "PostgreSQL from VPC"
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-rds-from-vpc"
  }
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_allowed_sgs" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.rds.id
  description                  = "PostgreSQL from allowed security group"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value

  tags = {
    Name = "${var.name_prefix}-rds-from-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "rds_all" {
  security_group_id = aws_security_group.rds.id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-rds-egress"
  }
}

# ==================== Subnet Group ====================

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-rds"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rds-subnet-group"
    Component = "rds"
  })
}

# ==================== Parameter Group ====================

resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${var.name_prefix}-aurora-pg16"
  family      = "aurora-postgresql16"
  description = "Aurora PostgreSQL 16 parameter group for ${var.name_prefix}"

  # Performance optimizations for serverless
  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking > 1 second
  }

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-aurora-pg16"
    Component = "rds"
  })
}

# ==================== Aurora Cluster ====================

resource "aws_rds_cluster" "main" {
  cluster_identifier = "${var.name_prefix}-aurora"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = "16.4"
  database_name      = var.database_name
  master_username    = var.master_username
  master_password    = random_password.master.result

  db_subnet_group_name            = aws_db_subnet_group.main.name
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name
  vpc_security_group_ids          = [aws_security_group.rds.id]

  # Serverless v2 configuration
  serverlessv2_scaling_configuration {
    min_capacity = var.min_capacity
    max_capacity = var.max_capacity
  }

  # Storage encryption
  storage_encrypted = true
  kms_key_id        = var.storage_kms_key_arn

  # Backup configuration
  backup_retention_period   = var.backup_retention_period
  preferred_backup_window   = "03:00-04:00"
  copy_tags_to_snapshot     = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.name_prefix}-aurora-final"

  # Maintenance
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  apply_immediately            = var.environment != "prod"

  # Enhanced monitoring and logging
  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-aurora-cluster"
    Component = "rds"
  })

  lifecycle {
    ignore_changes = [master_password]
  }
}

# ==================== Aurora Instance ====================

resource "aws_rds_cluster_instance" "main" {
  identifier         = "${var.name_prefix}-aurora-instance-1"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  # Performance Insights
  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_retention_period
  performance_insights_kms_key_id       = var.performance_insights_enabled ? var.secrets_kms_key_arn : null

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  # Apply immediately in non-prod
  apply_immediately = var.environment != "prod"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-aurora-instance-1"
    Component = "rds"
  })
}

# ==================== Enhanced Monitoring IAM Role ====================

resource "aws_iam_role" "rds_monitoring" {
  name = "${var.name_prefix}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rds-monitoring"
    Component = "rds"
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
