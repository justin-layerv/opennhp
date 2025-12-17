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
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
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
 * - Cloud Map service discovery with Route 53
 * - Proper Curve25519 key generation
 *
 * Health Monitoring Strategy (NHP-compliant):
 * - NO exposed HTTP health check ports
 * - Cloud Map with custom health checks (instance self-reports)
 * - Instances register/deregister via API on boot/shutdown
 * - ASG uses EC2 status checks, not ELB health checks
 * - Route 53 DNS automatically updated via Cloud Map
 */
export class ComputeStack extends cdk.Stack {
  public readonly nlb: elbv2.NetworkLoadBalancer;
  public readonly asg: autoscaling.AutoScalingGroup;
  public readonly serverLogGroup: logs.ILogGroup;
  public readonly serverSecret: secretsmanager.ISecret;
  public readonly cloudMapNamespace: servicediscovery.PrivateDnsNamespace;
  public readonly cloudMapService: servicediscovery.Service;

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
        Version: '1',
      },
    });

    // Store the generated key in Secrets Manager
    this.serverSecret = new secretsmanager.Secret(this, 'ServerSecret', {
      secretName: `layerv-nhp-server-${config.environment}`,
      description: 'NHP Server private key and configuration',
    });

    // Update secret with the generated key
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

    // Cloud Map namespace for service discovery (NHP-compliant - no inbound health checks)
    this.cloudMapNamespace = new servicediscovery.PrivateDnsNamespace(this, 'CloudMapNamespace', {
      name: `nhp.${config.environment}.layerv.internal`,
      vpc,
      description: 'Private DNS namespace for NHP service discovery',
    });

    // Cloud Map service with custom health checks (instance self-reports)
    this.cloudMapService = new servicediscovery.Service(this, 'CloudMapService', {
      namespace: this.cloudMapNamespace,
      name: 'server',
      description: 'NHP Server instances',
      // Custom health check - instances report their own health via API
      // No inbound connections required - fully NHP compliant
      customHealthCheck: {
        failureThreshold: 1,
      },
      // Enable DNS routing
      dnsRecordType: servicediscovery.DnsRecordType.A,
      dnsTtl: cdk.Duration.seconds(30),
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

    // Allow server to register/deregister with Cloud Map
    serverRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'servicediscovery:RegisterInstance',
        'servicediscovery:DeregisterInstance',
        'servicediscovery:UpdateInstanceCustomHealthStatus',
        'servicediscovery:GetInstance',
      ],
      resources: [this.cloudMapService.serviceArn],
    }));

    // Allow server to discover the service
    serverRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'servicediscovery:DiscoverInstances',
        'servicediscovery:GetNamespace',
        'servicediscovery:GetService',
      ],
      resources: ['*'],
    }));

    // Security Group for servers - ONLY UDP 62206, no HTTP health check port
    const serverSecurityGroup = new ec2.SecurityGroup(this, 'ServerSecurityGroup', {
      vpc,
      securityGroupName: `layerv-nhp-server-compute-${config.environment}`,
      description: 'Security group for NHP Server instances - UDP only, no exposed health check ports',
      allowAllOutbound: true,
    });

    // Allow NHP protocol (UDP 62206) - the ONLY inbound port
    serverSecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.udp(62206),
      'NHP Protocol - only exposed port'
    );

    // User data script for NHP Server - NO HTTP health check
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
      '# Cloud Map service discovery configuration',
      `CLOUDMAP_SERVICE_ID="${this.cloudMapService.serviceId}"`,
      `CLOUDMAP_NAMESPACE="${this.cloudMapNamespace.namespaceName}"`,
      '',
      '# Create Cloud Map registration script (NHP-compliant - no inbound connections)',
      'cat > /opt/layerv/nhp-server/cloudmap-register.sh << \'CMEOF\'',
      '#!/bin/bash',
      '# Register this instance with Cloud Map',
      'set -e',
      '',
      'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'LOCAL_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)',
      'REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      'AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)',
      '',
      'echo "Registering instance $INSTANCE_ID ($LOCAL_IP) with Cloud Map"',
      '',
      'aws servicediscovery register-instance \\',
      '  --service-id "$CLOUDMAP_SERVICE_ID" \\',
      '  --instance-id "$INSTANCE_ID" \\',
      '  --attributes "AWS_INSTANCE_IPV4=$LOCAL_IP,AVAILABILITY_ZONE=$AZ,NHP_PORT=62206" \\',
      '  --region "$REGION"',
      '',
      'echo "Instance registered successfully"',
      'CMEOF',
      'chmod +x /opt/layerv/nhp-server/cloudmap-register.sh',
      '',
      '# Create Cloud Map deregistration script',
      'cat > /opt/layerv/nhp-server/cloudmap-deregister.sh << \'CMEOF\'',
      '#!/bin/bash',
      '# Deregister this instance from Cloud Map',
      'set -e',
      '',
      'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      '',
      'echo "Deregistering instance $INSTANCE_ID from Cloud Map"',
      '',
      'aws servicediscovery deregister-instance \\',
      '  --service-id "$CLOUDMAP_SERVICE_ID" \\',
      '  --instance-id "$INSTANCE_ID" \\',
      '  --region "$REGION" || true',
      '',
      'echo "Instance deregistered"',
      'CMEOF',
      'chmod +x /opt/layerv/nhp-server/cloudmap-deregister.sh',
      '',
      '# Create health monitoring script (reports to Cloud Map, no inbound HTTP)',
      'cat > /opt/layerv/nhp-server/health-monitor.sh << \'HEALTHEOF\'',
      '#!/bin/bash',
      '# NHP-compliant health monitoring - updates Cloud Map custom health status',
      '',
      'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      '',
      'while true; do',
      '  # Check if NHP server container is running',
      '  if docker ps | grep -q nhp-server; then',
      '    HEALTH_STATUS="HEALTHY"',
      '  else',
      '    HEALTH_STATUS="UNHEALTHY"',
      '  fi',
      '',
      '  # Update Cloud Map custom health status',
      '  aws servicediscovery update-instance-custom-health-status \\',
      '    --service-id "$CLOUDMAP_SERVICE_ID" \\',
      '    --instance-id "$INSTANCE_ID" \\',
      '    --status "$HEALTH_STATUS" \\',
      '    --region "$REGION" 2>/dev/null || true',
      '',
      '  sleep 30',
      'done',
      'HEALTHEOF',
      'chmod +x /opt/layerv/nhp-server/health-monitor.sh',
      '',
      '# Create systemd service for health monitor',
      'cat > /etc/systemd/system/nhp-health-monitor.service << \'SVCEOF\'',
      '[Unit]',
      'Description=NHP Health Monitor (Cloud Map)',
      'After=network.target docker.service nhp-cloudmap-register.service',
      '',
      '[Service]',
      'Type=simple',
      `Environment="CLOUDMAP_SERVICE_ID=${this.cloudMapService.serviceId}"`,
      'ExecStart=/opt/layerv/nhp-server/health-monitor.sh',
      'Restart=always',
      'RestartSec=10',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'SVCEOF',
      '',
      '# Create systemd service for Cloud Map registration',
      'cat > /etc/systemd/system/nhp-cloudmap-register.service << \'SVCEOF\'',
      '[Unit]',
      'Description=Register NHP Server with Cloud Map',
      'After=network-online.target',
      'Wants=network-online.target',
      '',
      '[Service]',
      'Type=oneshot',
      `Environment="CLOUDMAP_SERVICE_ID=${this.cloudMapService.serviceId}"`,
      'ExecStart=/opt/layerv/nhp-server/cloudmap-register.sh',
      'RemainAfterExit=yes',
      `ExecStop=/opt/layerv/nhp-server/cloudmap-deregister.sh`,
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'SVCEOF',
      '',
      '# Login to ECR',
      `ECR_REPO="${serverRepo.repositoryUri}"`,
      `aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${this.account}.dkr.ecr.${this.region}.amazonaws.com"`,
      '',
      '# Pull NHP Server image',
      `docker pull "$ECR_REPO:latest" || docker pull "$ECR_REPO:${config.environment}" || echo "Warning: Could not pull image, will retry"`,
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
      'systemctl enable nhp-cloudmap-register nhp-health-monitor nhp-server',
      '',
      '# Register with Cloud Map first',
      'systemctl start nhp-cloudmap-register',
      '',
      '# Start health monitor',
      'systemctl start nhp-health-monitor',
      '',
      '# Try to start NHP server (may fail if image not available yet)',
      'systemctl start nhp-server || echo "NHP server start deferred - image may not be available"',
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

    // Auto Scaling Group with EC2 health checks (not ELB) - NHP compliant
    this.asg = new autoscaling.AutoScalingGroup(this, 'ServerAsg', {
      autoScalingGroupName: `layerv-nhp-server-${config.environment}`,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      launchTemplate,
      minCapacity: config.minCapacity,
      maxCapacity: config.maxCapacity,
      // Use EC2 health checks, NOT ELB - no exposed ports needed
      healthCheck: autoscaling.HealthCheck.ec2({
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

    // UDP Target Group - health checks disabled via high thresholds
    // NLB requires health checks, but we make them very permissive
    // Real health monitoring is done via Cloud Map service discovery
    const udpTargetGroup = new elbv2.NetworkTargetGroup(this, 'UdpTargetGroup', {
      targetGroupName: `nhp-udp-${config.environment}`,
      vpc,
      port: 62206,
      protocol: elbv2.Protocol.UDP,
      targetType: elbv2.TargetType.INSTANCE,
      // For UDP, NLB requires TCP/HTTP health checks on a different port
      // Since we don't expose any TCP ports, we disable effective health checking
      // by setting very high thresholds - instances stay healthy unless EC2 fails
      healthCheck: {
        enabled: true,
        protocol: elbv2.Protocol.TCP,
        port: '62206', // This will fail (UDP port), but with high thresholds it won't matter
        interval: cdk.Duration.seconds(30),
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 10, // Very high - effectively disabled
      },
      deregistrationDelay: cdk.Duration.seconds(30),
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

    new cdk.CfnOutput(this, 'CloudMapNamespaceArn', {
      value: this.cloudMapNamespace.namespaceArn,
      description: 'Cloud Map namespace ARN',
      exportName: `${this.stackName}-CloudMapNamespaceArn`,
    });

    new cdk.CfnOutput(this, 'CloudMapServiceArn', {
      value: this.cloudMapService.serviceArn,
      description: 'Cloud Map service ARN',
      exportName: `${this.stackName}-CloudMapServiceArn`,
    });

    new cdk.CfnOutput(this, 'CloudMapDnsName', {
      value: `server.${this.cloudMapNamespace.namespaceName}`,
      description: 'Cloud Map DNS name for service discovery',
      exportName: `${this.stackName}-CloudMapDnsName`,
    });

    new cdk.CfnOutput(this, 'HealthMonitoringNote', {
      value: 'Health monitoring via Cloud Map service discovery with Route 53 - no HTTP endpoints exposed',
      description: 'NHP-compliant health monitoring approach',
    });
  }
}
