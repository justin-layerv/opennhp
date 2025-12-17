import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

export interface NetworkStackProps extends cdk.StackProps {
  config: {
    environment: string;
    domainName: string;
  };
}

/**
 * Network Stack
 *
 * Creates the VPC and networking infrastructure for the LayerV control plane:
 * - VPC with 3 AZs
 * - Public subnets (for NLB)
 * - Private subnets (for NHP Servers)
 * - Isolated subnets (for databases)
 * - NAT Gateways for outbound access
 * - VPC Endpoints for AWS services
 *
 * Note: Security groups for compute resources are created in ComputeStack
 * to keep network concerns separate from compute configuration.
 */
export class NetworkStack extends cdk.Stack {
  public readonly vpc: ec2.IVpc;
  public readonly dataSecurityGroup: ec2.ISecurityGroup;

  constructor(scope: Construct, id: string, props: NetworkStackProps) {
    super(scope, id, props);

    const { config } = props;

    // VPC
    this.vpc = new ec2.Vpc(this, 'ControlPlaneVpc', {
      vpcName: `layerv-nhp-${config.environment}`,
      maxAzs: 3,
      ipAddresses: ec2.IpAddresses.cidr('10.100.0.0/16'),

      subnetConfiguration: [
        {
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
          mapPublicIpOnLaunch: true,
        },
        {
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
        {
          name: 'Isolated',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],

      natGateways: config.environment === 'prod' ? 3 : 1,

      // Flow logs for debugging
      flowLogs: {
        'FlowLogs': {
          trafficType: ec2.FlowLogTrafficType.ALL,
          destination: ec2.FlowLogDestination.toCloudWatchLogs(),
        },
      },
    });

    // Security Group for Data Layer (etcd, DB)
    // Note: Server security groups are created in ComputeStack
    this.dataSecurityGroup = new ec2.SecurityGroup(this, 'DataSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: `layerv-nhp-data-${config.environment}`,
      description: 'Security group for NHP data layer',
      allowAllOutbound: false,
    });

    // Allow etcd client access from private subnets (servers)
    this.dataSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(2379),
      'etcd client port from VPC'
    );

    // Allow etcd peer communication
    this.dataSecurityGroup.addIngressRule(
      this.dataSecurityGroup,
      ec2.Port.tcp(2380),
      'etcd peer port'
    );

    // Allow outbound to VPC for etcd peer communication
    this.dataSecurityGroup.addEgressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(2380),
      'etcd peer outbound'
    );

    // Allow HTTPS outbound for AWS APIs
    this.dataSecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'HTTPS for AWS APIs'
    );

    // VPC Endpoints for AWS services (reduces NAT costs and enables private subnet access)
    // S3 Gateway Endpoint (free)
    this.vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });

    // ECR endpoints for pulling container images
    this.vpc.addInterfaceEndpoint('EcrEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.ECR,
      privateDnsEnabled: true,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    this.vpc.addInterfaceEndpoint('EcrDockerEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
      privateDnsEnabled: true,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // CloudWatch Logs endpoint
    this.vpc.addInterfaceEndpoint('LogsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      privateDnsEnabled: true,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Secrets Manager endpoint
    this.vpc.addInterfaceEndpoint('SecretsManagerEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      privateDnsEnabled: true,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Cloud Map / Service Discovery endpoint (for Cloud Map API calls)
    this.vpc.addInterfaceEndpoint('ServiceDiscoveryEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUD_MAP_SERVICE_DISCOVERY,
      privateDnsEnabled: true,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Outputs
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID',
      exportName: `${this.stackName}-VpcId`,
    });

    new cdk.CfnOutput(this, 'PrivateSubnets', {
      value: this.vpc.privateSubnets.map(s => s.subnetId).join(','),
      description: 'Private Subnet IDs',
      exportName: `${this.stackName}-PrivateSubnets`,
    });
  }
}
