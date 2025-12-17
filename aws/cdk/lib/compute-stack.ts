import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import { DataStack } from './data-stack';

export interface ComputeStackProps extends cdk.StackProps {
  vpc: ec2.IVpc;
  dataStack: DataStack;
  serverRepo: ecr.IRepository;
  config: {
    environment: string;
    domainName: string;
    multiTenant: boolean;
    minCapacity: number;
    maxCapacity: number;
  };
}

/**
 * Compute Stack
 *
 * Deploys the NHP Server compute infrastructure:
 * - Auto Scaling Group with NHP Server instances
 * - Network Load Balancer for UDP traffic
 * - IAM roles and instance profiles
 * - CloudWatch log groups
 * - Proper Curve25519 key generation
 */
export class ComputeStack extends cdk.Stack {
  public readonly nlb: elbv2.NetworkLoadBalancer;
  public readonly asg: autoscaling.AutoScalingGroup;
  public readonly serverLogGroup: logs.ILogGroup;
  public readonly serverSecret: secretsmanager.ISecret;

  constructor(scope: Construct, id: string, props: ComputeStackProps) {
    super(scope, id, props);

    const { vpc, dataStack, serverRepo, config } = props;

    // Lambda for generating Curve25519 keys
    const keyGenLambda = new lambda.Function(this, 'KeyGenLambda', {
      functionName: `layerv-nhp-keygen-${config.environment}`,
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(`
const crypto = require('crypto');

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event));

  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId };
  }

  // Generate 32 random bytes for Curve25519 private key
  const privateKey = crypto.randomBytes(32);

  // Apply Curve25519 clamping
  privateKey[0] &= 248;
  privateKey[31] = (privateKey[31] & 127) | 64;

  // Base64 encode
  const privateKeyBase64 = privateKey.toString('base64');

  // Derive public key using Node.js crypto
  const keyPair = crypto.generateKeyPairSync('x25519');
  // For simplicity, we'll just use the private key - public key derivation
  // happens in the NHP server itself

  return {
    PhysicalResourceId: \`nhp-key-\${Date.now()}\`,
    Data: {
      PrivateKeyBase64: privateKeyBase64,
    },
  };
};
      `),
    });

    // Custom resource to generate keys
    const keyGenProvider = new cr.Provider(this, 'KeyGenProvider', {
      onEventHandler: keyGenLambda,
    });

    const keyGenResource = new cdk.CustomResource(this, 'KeyGenResource', {
      serviceToken: keyGenProvider.serviceToken,
      properties: {
        // Force regeneration if needed by changing this
        Version: '1',
      },
    });

    // Store the generated key in Secrets Manager
    this.serverSecret = new secretsmanager.Secret(this, 'ServerSecret', {
      secretName: `layerv-nhp-server-${config.environment}`,
      description: 'NHP Server private key and configuration',
    });

    // Update secret with the generated key using a custom resource
    const updateSecretLambda = new lambda.Function(this, 'UpdateSecretLambda', {
      functionName: `layerv-nhp-update-secret-${config.environment}`,
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(`
const { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event));

  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId };
  }

  const client = new SecretsManagerClient({});
  const secretId = event.ResourceProperties.SecretId;
  const privateKey = event.ResourceProperties.PrivateKeyBase64;
  const hostname = event.ResourceProperties.Hostname;
  const environment = event.ResourceProperties.Environment;

  // Check if secret already has a value (don't overwrite existing keys)
  try {
    const existing = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    if (existing.SecretString) {
      const parsed = JSON.parse(existing.SecretString);
      if (parsed.privateKey && parsed.privateKey.length === 44) {
        console.log('Secret already has a valid key, not overwriting');
        return { PhysicalResourceId: event.PhysicalResourceId || secretId };
      }
    }
  } catch (e) {
    console.log('No existing secret value, will create new');
  }

  const secretValue = JSON.stringify({
    privateKey: privateKey,
    hostname: hostname,
    environment: environment,
  });

  await client.send(new PutSecretValueCommand({
    SecretId: secretId,
    SecretString: secretValue,
  }));

  return { PhysicalResourceId: event.PhysicalResourceId || secretId };
};
      `),
    });

    this.serverSecret.grantWrite(updateSecretLambda);
    this.serverSecret.grantRead(updateSecretLambda);

    const updateSecretProvider = new cr.Provider(this, 'UpdateSecretProvider', {
      onEventHandler: updateSecretLambda,
    });

    new cdk.CustomResource(this, 'UpdateSecretResource', {
      serviceToken: updateSecretProvider.serviceToken,
      properties: {
        SecretId: this.serverSecret.secretArn,
        PrivateKeyBase64: keyGenResource.getAttString('PrivateKeyBase64'),
        Hostname: config.domainName,
        Environment: config.environment,
      },
    });

    // CloudWatch Log Group for servers
    this.serverLogGroup = new logs.LogGroup(this, 'ServerLogGroup', {
      logGroupName: `/layerv/nhp-server/${config.environment}`,
      retention: config.environment === 'prod'
        ? logs.RetentionDays.ONE_YEAR
        : logs.RetentionDays.ONE_MONTH,
      removalPolicy: config.environment === 'prod'
        ? cdk.RemovalPolicy.RETAIN
        : cdk.RemovalPolicy.DESTROY,
    });

    // IAM Role for NHP Server instances
    const serverRole = new iam.Role(this, 'ServerRole', {
      roleName: `layerv-nhp-server-${config.environment}`,
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
      ],
    });

    // Allow server to read its secrets
    this.serverSecret.grantRead(serverRole);

    // Allow server to access etcd secrets
    if (dataStack.etcdSecret) {
      dataStack.etcdSecret.grantRead(serverRole);
    }

    // Allow server to pull from ECR
    serverRepo.grantPull(serverRole);

    // Allow server to publish custom metrics
    serverRole.addToPolicy(new iam.PolicyStatement({
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'cloudwatch:namespace': 'LayerV/NHP',
        },
      },
    }));

    // Security Group for servers
    const serverSecurityGroup = new ec2.SecurityGroup(this, 'ServerSecurityGroup', {
      vpc,
      securityGroupName: `layerv-nhp-server-compute-${config.environment}`,
      description: 'Security group for NHP Server instances',
      allowAllOutbound: true,
    });

    // Allow NHP protocol (UDP 62206)
    serverSecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.udp(62206),
      'NHP Protocol'
    );

    // Allow health checks from VPC (NLB uses private IPs)
    serverSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(8080),
      'Health check from NLB'
    );

    // User data script for NHP Server
    const userData = ec2.UserData.forLinux();

    // Build etcd config section conditionally
    const etcdConfigSection = config.multiTenant && dataStack.etcdEndpoint ? `
# Configure etcd connection for multi-tenant
cat > /opt/layerv/nhp-server/etc/remote.toml << 'REMOTEEOF'
Provider = "etcd"
Key = "/nhp/config"
Endpoints = ["${dataStack.etcdEndpoint}"]
REMOTEEOF
` : '';

    userData.addCommands(
      '#!/bin/bash',
      'set -ex',
      '',
      '# Log everything to file and console',
      'exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1',
      'echo "Starting NHP Server installation at $(date)"',
      '',
      '# Install dependencies',
      'export DEBIAN_FRONTEND=noninteractive',
      'apt-get update -y',
      'apt-get install -y awscli jq docker.io curl',
      '',
      '# Enable and start Docker',
      'systemctl enable docker',
      'systemctl start docker',
      '',
      '# Wait for Docker to be ready',
      'for i in {1..30}; do docker info && break || sleep 2; done',
      '',
      `# Get configuration from Secrets Manager`,
      `SECRET_ARN="${this.serverSecret.secretArn}"`,
      `REGION="${this.region}"`,
      'SECRET=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "$REGION" --query SecretString --output text)',
      'PRIVATE_KEY=$(echo "$SECRET" | jq -r ".privateKey")',
      'HOSTNAME=$(echo "$SECRET" | jq -r ".hostname")',
      '',
      '# Get instance metadata (IMDSv2)',
      'TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)',
      'AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)',
      '',
      '# Create config directory',
      'mkdir -p /opt/layerv/nhp-server/etc',
      'mkdir -p /opt/layerv/nhp-server/log',
      '',
      '# Create config.toml with proper variable substitution',
      'cat > /opt/layerv/nhp-server/etc/config.toml << CONFIGEOF',
      'PrivateKeyBase64 = "${PRIVATE_KEY}"',
      'DefaultCipherScheme = 1',
      'ListenIp = ""',
      'ListenPort = 62206',
      'Hostname = "${HOSTNAME}"',
      'LogLevel = 3',
      'DisableAgentValidation = false',
      '',
      '[webrtc]',
      'Enable = false',
      'CONFIGEOF',
      '',
      '# Substitute variables in config',
      'sed -i "s/\\${PRIVATE_KEY}/$PRIVATE_KEY/g" /opt/layerv/nhp-server/etc/config.toml',
      'sed -i "s/\\${HOSTNAME}/$HOSTNAME/g" /opt/layerv/nhp-server/etc/config.toml',
      '',
      etcdConfigSection,
      '',
      '# Login to ECR',
      `ECR_REPO="${serverRepo.repositoryUri}"`,
      `aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${this.account}.dkr.ecr.${this.region}.amazonaws.com"`,
      '',
      '# Pull NHP Server image',
      'docker pull "$ECR_REPO:latest" || docker pull "$ECR_REPO:${config.environment}" || echo "Warning: Could not pull image, will retry"',
      '',
      '# Create health check script',
      'cat > /opt/layerv/nhp-server/healthcheck.sh << \'HEALTHEOF\'',
      '#!/bin/bash',
      '# Simple health check - verify NHP server process is running',
      'if docker ps | grep -q nhp-server; then',
      '  echo "healthy"',
      '  exit 0',
      'else',
      '  echo "unhealthy"',
      '  exit 1',
      'fi',
      'HEALTHEOF',
      'chmod +x /opt/layerv/nhp-server/healthcheck.sh',
      '',
      '# Create simple health check HTTP server using socat',
      'apt-get install -y socat',
      'cat > /opt/layerv/nhp-server/health-server.sh << \'SERVEREOF\'',
      '#!/bin/bash',
      'while true; do',
      '  if /opt/layerv/nhp-server/healthcheck.sh > /dev/null 2>&1; then',
      '    RESPONSE="HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nok"',
      '  else',
      '    RESPONSE="HTTP/1.1 503 Service Unavailable\\r\\nContent-Type: text/plain\\r\\nContent-Length: 5\\r\\n\\r\\nerror"',
      '  fi',
      '  echo -e "$RESPONSE" | socat - TCP-LISTEN:8080,reuseaddr',
      'done',
      'SERVEREOF',
      'chmod +x /opt/layerv/nhp-server/health-server.sh',
      '',
      '# Create systemd service for health check server',
      'cat > /etc/systemd/system/nhp-health.service << \'SVCEOF\'',
      '[Unit]',
      'Description=NHP Health Check Server',
      'After=network.target docker.service',
      '',
      '[Service]',
      'Type=simple',
      'ExecStart=/opt/layerv/nhp-server/health-server.sh',
      'Restart=always',
      'RestartSec=5',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'SVCEOF',
      '',
      '# Create systemd service for NHP Server container',
      'cat > /etc/systemd/system/nhp-server.service << SVCEOF',
      '[Unit]',
      'Description=LayerV NHP Server',
      'After=network.target docker.service',
      'Requires=docker.service',
      '',
      '[Service]',
      'Type=simple',
      'Restart=always',
      'RestartSec=10',
      `ExecStartPre=-/usr/bin/docker stop nhp-server`,
      `ExecStartPre=-/usr/bin/docker rm nhp-server`,
      `ExecStart=/usr/bin/docker run --rm --name nhp-server \\\\`,
      '  --net=host \\\\',
      '  -v /opt/layerv/nhp-server/etc:/etc/nhp:ro \\\\',
      '  -v /opt/layerv/nhp-server/log:/var/log/nhp \\\\',
      `  ${serverRepo.repositoryUri}:latest`,
      'ExecStop=/usr/bin/docker stop nhp-server',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'SVCEOF',
      '',
      '# Start services',
      'systemctl daemon-reload',
      'systemctl enable nhp-health nhp-server',
      'systemctl start nhp-health',
      '',
      '# Try to start NHP server (may fail if image not available yet)',
      'systemctl start nhp-server || echo "NHP server start deferred - image may not be available"',
      '',
      '# Send custom metric for successful boot',
      `aws cloudwatch put-metric-data --namespace "LayerV/NHP" --metric-name "InstanceBoot" --value 1 --dimensions "Environment=${config.environment},InstanceId=$INSTANCE_ID" --region "$REGION"`,
      '',
      'echo "NHP Server installation complete at $(date)"',
    );

    // Launch Template
    const launchTemplate = new ec2.LaunchTemplate(this, 'ServerLaunchTemplate', {
      launchTemplateName: `layerv-nhp-server-${config.environment}`,
      instanceType: config.environment === 'prod'
        ? ec2.InstanceType.of(ec2.InstanceClass.C6I, ec2.InstanceSize.XLARGE)
        : ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: ec2.MachineImage.fromSsmParameter(
        '/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id'
      ),
      role: serverRole,
      securityGroup: serverSecurityGroup,
      userData,
      blockDevices: [
        {
          deviceName: '/dev/sda1',
          volume: ec2.BlockDeviceVolume.ebs(50, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            encrypted: true,
          }),
        },
      ],
    });

    // Auto Scaling Group
    this.asg = new autoscaling.AutoScalingGroup(this, 'ServerAsg', {
      autoScalingGroupName: `layerv-nhp-server-${config.environment}`,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      launchTemplate,
      minCapacity: config.minCapacity,
      maxCapacity: config.maxCapacity,
      healthCheck: autoscaling.HealthCheck.elb({
        grace: cdk.Duration.minutes(5),
      }),
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate({
        maxBatchSize: 1,
        minInstancesInService: config.minCapacity,
        pauseTime: cdk.Duration.minutes(5),
      }),
    });

    // Scaling policies
    this.asg.scaleOnCpuUtilization('CpuScaling', {
      targetUtilizationPercent: 70,
      cooldown: cdk.Duration.minutes(5),
    });

    this.asg.scaleOnIncomingBytes('NetworkScaling', {
      targetBytesPerSecond: 10 * 1024 * 1024, // 10 MB/s
      cooldown: cdk.Duration.minutes(5),
    });

    // Network Load Balancer
    this.nlb = new elbv2.NetworkLoadBalancer(this, 'ServerNlb', {
      loadBalancerName: `layerv-nhp-${config.environment}`,
      vpc,
      internetFacing: true,
      crossZoneEnabled: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

    // UDP Target Group for NHP Protocol
    const udpTargetGroup = new elbv2.NetworkTargetGroup(this, 'UdpTargetGroup', {
      targetGroupName: `nhp-udp-${config.environment}`,
      vpc,
      port: 62206,
      protocol: elbv2.Protocol.UDP,
      targetType: elbv2.TargetType.INSTANCE,
      healthCheck: {
        enabled: true,
        protocol: elbv2.Protocol.TCP,
        port: '8080',
        interval: cdk.Duration.seconds(30),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 2,
      },
    });

    // Attach ASG to target group
    this.asg.attachToNetworkTargetGroup(udpTargetGroup);

    // UDP Listener
    this.nlb.addListener('UdpListener', {
      port: 62206,
      protocol: elbv2.Protocol.UDP,
      defaultTargetGroups: [udpTargetGroup],
    });

    // Outputs
    new cdk.CfnOutput(this, 'NlbDnsName', {
      value: this.nlb.loadBalancerDnsName,
      description: 'NLB DNS Name (use for nhp.layerv.ai)',
      exportName: `${this.stackName}-NlbDnsName`,
    });

    new cdk.CfnOutput(this, 'AsgName', {
      value: this.asg.autoScalingGroupName,
      description: 'Auto Scaling Group Name',
      exportName: `${this.stackName}-AsgName`,
    });

    new cdk.CfnOutput(this, 'ServerSecretArn', {
      value: this.serverSecret.secretArn,
      description: 'Server Secret ARN',
      exportName: `${this.stackName}-ServerSecretArn`,
    });
  }
}
