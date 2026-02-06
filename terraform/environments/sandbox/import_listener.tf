# Temporary import block - remove after first successful apply.
#
# The HTTPS listener was recreated out-of-band to fix a preserve_client_ip
# issue that blocked TLS-terminated traffic. This imports the new listener
# into Terraform state so it doesn't try to create a duplicate.
import {
  to = module.nhp.module.compute.aws_lb_listener.https[0]
  id = "arn:aws:elasticloadbalancing:us-east-2:767397897469:listener/net/layerv-nhp-sandbox-nlb/3f7f2543fe6a9129/6f7023305f78b414"
}
