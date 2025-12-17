#!/bin/bash
#
# LayerV NHP Access Controller - Quick Deploy Script
#
# Usage:
#   ./deploy-ac.sh --org-id <org-id> --api-key <api-key> --vpc-id <vpc-id> --subnet-id <subnet-id>
#
# This script deploys the NHP-AC CloudFormation stack into your AWS account.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
STACK_NAME="layerv-nhp-ac"
INSTANCE_TYPE="t3.medium"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
LAYERV_SERVER="nhp.layerv.ai"
TEMPLATE_URL="https://layerv-public.s3.amazonaws.com/cloudformation/nhp-ac.yaml"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║     LayerV NHP Access Controller - Deployment Script         ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --org-id        Your LayerV Organization ID"
    echo "  --api-key       Your LayerV API Key"
    echo "  --vpc-id        AWS VPC ID where AC will be deployed"
    echo "  --subnet-id     AWS Subnet ID for the AC instance"
    echo ""
    echo "Optional:"
    echo "  --stack-name    CloudFormation stack name (default: layerv-nhp-ac)"
    echo "  --instance-type EC2 instance type (default: t3.medium)"
    echo "  --region        AWS region (default: us-east-1)"
    echo "  --key-pair      EC2 Key Pair name for SSH access"
    echo "  --protected-cidrs  CIDRs of protected resources (default: 10.0.0.0/8)"
    echo "  --protected-ports  Ports to protect (default: 22,443,3306,5432,6379)"
    echo "  --public-ip     Associate public IP (true/false, default: false)"
    echo "  --help          Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --org-id acme-corp --api-key sk_live_xxx --vpc-id vpc-123 --subnet-id subnet-456"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --org-id)
            ORG_ID="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --vpc-id)
            VPC_ID="$2"
            shift 2
            ;;
        --subnet-id)
            SUBNET_ID="$2"
            shift 2
            ;;
        --stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        --instance-type)
            INSTANCE_TYPE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --key-pair)
            KEY_PAIR="$2"
            shift 2
            ;;
        --protected-cidrs)
            PROTECTED_CIDRS="$2"
            shift 2
            ;;
        --protected-ports)
            PROTECTED_PORTS="$2"
            shift 2
            ;;
        --public-ip)
            PUBLIC_IP="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Validate required parameters
print_banner

echo -e "${BLUE}Validating parameters...${NC}"

if [[ -z "$ORG_ID" ]]; then
    echo -e "${RED}Error: --org-id is required${NC}"
    usage
    exit 1
fi

if [[ -z "$API_KEY" ]]; then
    echo -e "${RED}Error: --api-key is required${NC}"
    usage
    exit 1
fi

if [[ -z "$VPC_ID" ]]; then
    echo -e "${RED}Error: --vpc-id is required${NC}"
    usage
    exit 1
fi

if [[ -z "$SUBNET_ID" ]]; then
    echo -e "${RED}Error: --subnet-id is required${NC}"
    usage
    exit 1
fi

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check AWS credentials
echo -e "${BLUE}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured. Please run 'aws configure' first.${NC}"
    exit 1
fi

AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}✓ AWS Account: $AWS_ACCOUNT${NC}"
echo -e "${GREEN}✓ Region: $REGION${NC}"

# Verify VPC exists
echo -e "${BLUE}Verifying VPC...${NC}"
if ! aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$REGION" &> /dev/null; then
    echo -e "${RED}Error: VPC $VPC_ID not found in region $REGION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ VPC: $VPC_ID${NC}"

# Verify Subnet exists
echo -e "${BLUE}Verifying Subnet...${NC}"
if ! aws ec2 describe-subnets --subnet-ids "$SUBNET_ID" --region "$REGION" &> /dev/null; then
    echo -e "${RED}Error: Subnet $SUBNET_ID not found in region $REGION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Subnet: $SUBNET_ID${NC}"

# Build CloudFormation parameters
PARAMS="ParameterKey=OrganizationId,ParameterValue=$ORG_ID"
PARAMS="$PARAMS ParameterKey=ACApiKey,ParameterValue=$API_KEY"
PARAMS="$PARAMS ParameterKey=LayerVServerEndpoint,ParameterValue=$LAYERV_SERVER"
PARAMS="$PARAMS ParameterKey=VpcId,ParameterValue=$VPC_ID"
PARAMS="$PARAMS ParameterKey=SubnetId,ParameterValue=$SUBNET_ID"
PARAMS="$PARAMS ParameterKey=InstanceType,ParameterValue=$INSTANCE_TYPE"

if [[ -n "$KEY_PAIR" ]]; then
    PARAMS="$PARAMS ParameterKey=KeyPairName,ParameterValue=$KEY_PAIR"
fi

if [[ -n "$PROTECTED_CIDRS" ]]; then
    PARAMS="$PARAMS ParameterKey=ProtectedCIDRs,ParameterValue=$PROTECTED_CIDRS"
fi

if [[ -n "$PROTECTED_PORTS" ]]; then
    PARAMS="$PARAMS ParameterKey=ProtectedPorts,ParameterValue=$PROTECTED_PORTS"
fi

if [[ -n "$PUBLIC_IP" ]]; then
    PARAMS="$PARAMS ParameterKey=AssociatePublicIp,ParameterValue=$PUBLIC_IP"
fi

# Deploy CloudFormation stack
echo ""
echo -e "${YELLOW}Deploying LayerV NHP-AC...${NC}"
echo -e "Stack Name: ${BLUE}$STACK_NAME${NC}"
echo -e "Region:     ${BLUE}$REGION${NC}"
echo -e "Instance:   ${BLUE}$INSTANCE_TYPE${NC}"
echo ""

# Check if stack already exists
if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" &> /dev/null; then
    echo -e "${YELLOW}Stack $STACK_NAME already exists. Updating...${NC}"
    ACTION="update-stack"
else
    echo -e "${BLUE}Creating new stack $STACK_NAME...${NC}"
    ACTION="create-stack"
fi

# Use local template if available, otherwise use S3
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_TEMPLATE="$SCRIPT_DIR/../cloudformation/nhp-ac.yaml"

if [[ -f "$LOCAL_TEMPLATE" ]]; then
    TEMPLATE_PARAM="--template-body file://$LOCAL_TEMPLATE"
else
    TEMPLATE_PARAM="--template-url $TEMPLATE_URL"
fi

# Deploy
aws cloudformation $ACTION \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    $TEMPLATE_PARAM \
    --parameters $PARAMS \
    --capabilities CAPABILITY_NAMED_IAM \
    --tags Key=layerv:organization,Value="$ORG_ID"

echo ""
echo -e "${BLUE}Waiting for deployment to complete...${NC}"
echo -e "${YELLOW}(This typically takes 3-5 minutes)${NC}"
echo ""

# Wait for stack to complete
if [[ "$ACTION" == "create-stack" ]]; then
    aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$REGION"
else
    aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" --region "$REGION"
fi

# Get outputs
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Deployment Complete!                             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='ACInstanceId'].OutputValue" \
    --output text)

PRIVATE_IP=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='ACPrivateIp'].OutputValue" \
    --output text)

echo -e "AC Instance ID:  ${BLUE}$INSTANCE_ID${NC}"
echo -e "AC Private IP:   ${BLUE}$PRIVATE_IP${NC}"
echo -e "Organization:    ${BLUE}$ORG_ID${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. The AC will auto-register with LayerV using your Organization ID"
echo "2. Configure protected resources in the LayerV console"
echo "3. Deploy agents to your users"
echo "4. Check logs: aws logs tail /layerv/nhp-ac/$STACK_NAME --region $REGION"
echo ""
echo -e "${GREEN}For support, visit https://layerv.ai/support${NC}"
