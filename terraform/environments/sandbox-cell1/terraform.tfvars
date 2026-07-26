# Sandbox cell1 configuration — lean, standalone NHP-server cell.
# Step 6 of the two-cell UDP substrate for the qURL Connector.
#
# Every value here is also the variable default (see variables.tf); they are
# pinned explicitly so the cell's identity is legible in one place and a future
# knob change is a tfvars edit, not a code edit.

# --- Cell identity (MUST stay distinct from cell0) ---------------------------
environment          = "sandbox-cell1" # infrastructure namespace: names and /sandbox-cell1/... SSM paths
protocol_environment = "sandbox"       # ticket/Authority environment shared with cell0
cell_id              = "cell1"
aws_region           = "us-east-2"
aws_account_id       = "767397897469" # sandbox account, shared with cell0

# --- Network isolation -------------------------------------------------------
# cell0 VPC        = 10.100.0.0/16
# cell0 relay DMZ  = 10.101.0.0/16
# Control VPC      = 10.102.0.0/16
# UDP proof runner = 10.103.0.0/28
# prod VPC         = 10.200.0.0/16 (separate account)
# cell1 VPC        = 10.104.0.0/16  <-- distinct, non-overlapping
vpc_cidr = "10.104.0.0/16"

# --- DNS ---------------------------------------------------------------------
domain_name    = "nhp.layerv.xyz"        # sandbox domain (NOT .ai); server-identity hostname
cell_dns_name  = "cell1.nhp.layerv.xyz"  # public A-alias -> cell1 NLB
hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)

# --- Server AMI --------------------------------------------------------------
# null -> modules/compute reads /sandbox-cell1/nhp/server/ami-id. That SSM
# parameter must be seeded (packer/CI, mirroring cell0's /sandbox path) before
# the first plan/apply. Pin an AMI id here to bypass the lookup.
server_ami_id = null

# --- Capacity (lean for a proof) ---------------------------------------------
min_capacity           = 1
max_capacity           = 2
green_standby_min_size = 0 # cold green standby; still publishes green TGs + switch SSM ARNs

# --- Server behavior (matches cell0 sandbox posture) -------------------------
log_level = 4 # debug

tags = {
  Organization = "LayerV"
  CostCenter   = "infrastructure"
  Owner        = "platform-team"
}
