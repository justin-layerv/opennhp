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
  nhp_cell0 = "layerv-nhp-sandbox-server"
  # The sandbox-cell1 root prefixes its compute module with the cell name, so
  # the live role carries "cell1" twice. Verified against the running node's
  # instance profile (arn:...:instance-profile/layerv-nhp-sandbox-cell1-cell1-server);
  # the singular form does not exist and makes the KMS key policy unresolvable.
  nhp_cell1                  = "layerv-nhp-sandbox-cell1-cell1-server"
  qurl_reverse_tunnel_server = "layerv-nhp-sandbox-frps"
}

# The repair association targets each exact ASG by name, read from the same
# canonical parameters the producer uses to discover the fleets.
#
# Both cells are blue/green, so both colours are listed. The active colour is
# runtime state and this association is plan-time state; targeting every colour
# covers whichever is active without re-encoding create-time colour into the
# plan. /<env>/nhp/server/asg-name is deliberately absent -- it is the
# colour-blind base/blue group, and targeting it is what left cell0's active
# green fleet with no collector installed and no attestations at all.
asg_name_ssm_parameters = {
  nhp_cell0 = [
    "/sandbox/nhp/server/blue-asg-name",
    "/sandbox/nhp/server/green-asg-name",
  ]
  nhp_cell1 = [
    "/sandbox-cell1/nhp/server/blue-asg-name",
    "/sandbox-cell1/nhp/server/green-asg-name",
  ]
  qurl_reverse_tunnel_server = [
    "/sandbox/nhp/reverse-tunnel-server/asg-name",
  ]
}
