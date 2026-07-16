module "control" {
  source = "../../../modules/connector-authority-foundation"

  environment                = var.environment
  aws_account_id             = var.aws_account_id
  vpc_cidr                   = var.vpc_cidr
  otp_email_from             = var.otp_email_from
  ses_configuration_set_name = var.ses_configuration_set_name
  tags                       = var.tags
}
