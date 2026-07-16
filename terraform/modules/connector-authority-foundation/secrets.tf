resource "aws_secretsmanager_secret" "otp_pepper" {
  name                    = "${local.name_prefix}-otp-pepper"
  description             = "Connector Authority OTP hash pepper; seed 48+ random bytes out of band before runtime publication"
  kms_key_id              = aws_kms_key.authority_data.arn
  recovery_window_in_days = local.is_prod ? 30 : 7

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-otp-pepper"
    Purpose = "Connector OTP challenge hashing"
  })
}
