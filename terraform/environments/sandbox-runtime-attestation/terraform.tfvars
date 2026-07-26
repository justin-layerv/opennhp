# Sandbox runtime-attestation store. Every value here is also the variable
# default; pinned explicitly so the store's identity is legible in one place.

environment = "sandbox"
aws_region  = "us-east-2"

# The producer only accepts a layerv-nhp-sandbox-* bucket ARN; this exact name
# is part of the published contract, not a label.
bucket_name = "layerv-nhp-sandbox-runtime-attestations"

# The three EC2 fleets whose live runtime the deployment manifest must prove.
# Each role may only s3:PutObject beneath runtime/${aws:userid}/ — self-bound to
# <role-id>:<instance-id> — and gets no list, read, delete, or
# overwrite-by-shared-prefix authority.
attested_node_roles = {
  nhp_cell0                  = "layerv-nhp-sandbox-server"
  nhp_cell1                  = "layerv-nhp-sandbox-cell1-server"
  qurl_reverse_tunnel_server = "layerv-nhp-sandbox-frps"
}

# The repair association targets each exact ASG by name, read from the same
# canonical parameters the producer uses to discover the fleets.
asg_name_ssm_parameters = {
  nhp_cell0                  = "/sandbox/nhp/server/asg-name"
  nhp_cell1                  = "/sandbox-cell1/nhp/server/asg-name"
  qurl_reverse_tunnel_server = "/sandbox/nhp/reverse-tunnel-server/asg-name"
}
