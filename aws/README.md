# LayerV NHP - AWS Deployment

This directory contains AWS deployment artifacts for LayerV NHP.

## Directory Structure

```
aws/
├── cloudformation/
│   └── nhp-ac.yaml          # CloudFormation template for AC deployment
├── scripts/
│   └── deploy-ac.sh         # Quick-start deployment script
├── configs/
│   └── onboarding-template.yaml  # Customer onboarding form
└── README.md
```

## Quick Start

### Prerequisites

1. AWS CLI installed and configured (`aws configure`)
2. LayerV Organization ID and API Key (from subscription)
3. Target VPC and Subnet IDs

### Deploy NHP-AC

```bash
./scripts/deploy-ac.sh \
  --org-id your-organization-id \
  --api-key your-api-key \
  --vpc-id vpc-0123456789abcdef0 \
  --subnet-id subnet-0123456789abcdef0
```

### Full Options

```bash
./scripts/deploy-ac.sh \
  --org-id acme-corp \
  --api-key sk_live_xxxxxxxxxxxx \
  --vpc-id vpc-0123456789abcdef0 \
  --subnet-id subnet-0123456789abcdef0 \
  --stack-name my-nhp-ac \
  --instance-type t3.medium \
  --region us-east-1 \
  --key-pair my-keypair \
  --protected-cidrs "10.0.0.0/8,172.16.0.0/12" \
  --protected-ports "22,443,3306,5432"
```

## CloudFormation Template

The `cloudformation/nhp-ac.yaml` template creates:

- EC2 instance running NHP-AC
- Security Group with NHP protocol rules
- IAM Role with minimal permissions
- Secrets Manager secret for credentials
- CloudWatch Log Group for AC logs
- CloudWatch Alarm for instance health

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| OrganizationId | Yes | LayerV Organization ID |
| ACApiKey | Yes | LayerV API Key |
| VpcId | Yes | VPC for deployment |
| SubnetId | Yes | Subnet for AC instance |
| InstanceType | No | EC2 instance type (default: t3.medium) |
| KeyPairName | No | SSH key pair |
| ProtectedCIDRs | No | CIDRs of protected resources |
| ProtectedPorts | No | Ports to protect |

### Deploy via AWS Console

1. Go to CloudFormation in AWS Console
2. Create Stack → Upload template
3. Upload `cloudformation/nhp-ac.yaml`
4. Fill in parameters
5. Acknowledge IAM capabilities
6. Create Stack

## Customer Onboarding

Use `configs/onboarding-template.yaml` to collect customer information:

1. Send template to customer
2. Customer fills out and returns
3. Provision customer in LayerV backend
4. Provide Organization ID and API Key
5. Customer runs deployment script

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CUSTOMER AWS ACCOUNT                       │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      Customer VPC                         │  │
│  │                                                           │  │
│  │  ┌─────────────┐                 ┌─────────────────────┐  │  │
│  │  │   NHP-AC    │                 │ Protected Resources │  │  │
│  │  │  (EC2)      │ ──────────────> │  - Databases        │  │  │
│  │  │             │  Opens access   │  - APIs             │  │  │
│  │  │ iptables/   │  via iptables   │  - SSH/RDP          │  │  │
│  │  │ ipset       │                 │                     │  │  │
│  │  └──────┬──────┘                 └─────────────────────┘  │  │
│  │         │                                                 │  │
│  └─────────┼─────────────────────────────────────────────────┘  │
│            │ UDP 62206                                          │
└────────────┼────────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────┐
│           LayerV Cloud                 │
│  ┌──────────────────────────────────┐  │
│  │         NHP Server               │  │
│  │   (Authentication & Policy)      │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

## Troubleshooting

### Check AC Status

```bash
# SSH to instance (if key pair provided)
ssh -i your-key.pem ubuntu@<instance-ip>

# Check service status
sudo systemctl status nhp-ac

# Check logs
sudo journalctl -u nhp-ac -f

# Check user-data log
cat /var/log/user-data.log
```

### CloudWatch Logs

```bash
aws logs tail /layerv/nhp-ac/<stack-name> --follow --region <region>
```

### Common Issues

1. **AC not connecting to LayerV Server**
   - Check Security Group allows UDP 62206 outbound
   - Verify NAT Gateway or public IP for outbound access
   - Check `/var/log/user-data.log` for errors

2. **Protected resources not accessible**
   - Verify resource CIDR is in ProtectedCIDRs
   - Check iptables rules: `sudo iptables -L -n`
   - Check ipset: `sudo ipset list`

3. **Stack creation failed**
   - Check CloudFormation events in AWS Console
   - Common: AMI not available in region, IAM permissions

## Support

- Documentation: https://docs.layerv.ai
- Support: support@layerv.ai
- Status: https://status.layerv.ai
