variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "waf_scope" {
  description = "WAF scope - CLOUDFRONT for CloudFront, REGIONAL for ALB/API Gateway"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.waf_scope)
    error_message = "WAF scope must be CLOUDFRONT or REGIONAL."
  }
}

variable "rate_limit_requests" {
  description = "Number of requests allowed per 5-minute period per IP"
  type        = number
  default     = 2000
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch"
  type        = bool
  default     = true
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for centralized security findings"
  type        = bool
  default     = true
}

variable "enable_aws_config" {
  description = "Enable AWS Config for configuration compliance monitoring"
  type        = bool
  default     = true
}

variable "config_recording_frequency" {
  description = "AWS Config recording frequency: CONTINUOUS (every change) or DAILY (once per 24h). DAILY reduces costs ~90%."
  type        = string
  default     = "DAILY"

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.config_recording_frequency)
    error_message = "config_recording_frequency must be CONTINUOUS or DAILY."
  }
}

variable "config_resource_types" {
  description = "Specific AWS resource types to record. When set, only these types are recorded instead of all supported types. Reduces Config costs by excluding high-churn resources."
  type        = list(string)
  default = [
    # Required by Config rules: ENCRYPTED_VOLUMES
    "AWS::EC2::Volume",
    # Required by Config rules: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
    "AWS::S3::Bucket",
    # Required by Config rules: INCOMING_SSH_DISABLED
    "AWS::EC2::SecurityGroup",
    # Required by Config rules: VPC_FLOW_LOGS_ENABLED
    "AWS::EC2::VPC",
    # Required by Config rules: IAM_USER_MFA_ENABLED, ROOT_ACCOUNT_MFA_ENABLED
    "AWS::IAM::User",
    # SecurityHub FSBP: instance metadata, IMDSv2
    "AWS::EC2::Instance",
    # SecurityHub FSBP: encryption, public access
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    # SecurityHub FSBP: public access checks
    "AWS::Lambda::Function",
    # SecurityHub FSBP: key rotation
    "AWS::KMS::Key",
    # SecurityHub FSBP: certificate expiration
    "AWS::ACM::Certificate",
    # SecurityHub FSBP: load balancer security
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    # SecurityHub FSBP: cluster/service configuration
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    # SecurityHub FSBP: ASG health checks
    "AWS::AutoScaling::AutoScalingGroup",
    # SecurityHub FSBP: topic encryption
    "AWS::SNS::Topic",
    # SecurityHub CIS: CloudTrail configuration
    "AWS::CloudTrail::Trail",
  ]
}

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API audit logging"
  type        = bool
  default     = true
}

# GuardDuty alerting configuration
variable "enable_guardduty_alerts" {
  description = "Enable GuardDuty finding alerts (Slack via main topic, email via dedicated topic)"
  type        = bool
  default     = false
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for Slack notifications via Chatbot (GuardDuty Slack + CloudWatch alarms). Email alerts use a separate dedicated topic."
  type        = string
  default     = null
}

variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty finding alerts"
  type        = list(string)
  default     = []
}

variable "guardduty_alert_severity_threshold" {
  description = "Minimum severity for GuardDuty alerts (1-8, where 7+ is High, 4-6.9 is Medium)"
  type        = number
  default     = 4 # Medium and above

  validation {
    condition     = var.guardduty_alert_severity_threshold >= 1 && var.guardduty_alert_severity_threshold <= 8
    error_message = "GuardDuty severity threshold must be between 1 and 8."
  }
}

variable "enable_slack_target" {
  description = "Enable separate Slack-optimized EventBridge target (requires AWS Chatbot integration)"
  type        = bool
  default     = true
}
