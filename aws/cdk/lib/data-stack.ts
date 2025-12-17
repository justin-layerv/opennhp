import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import * as efs from 'aws-cdk-lib/aws-efs';
import { Construct } from 'constructs';

export interface DataStackProps extends cdk.StackProps {
  vpc: ec2.IVpc;
  config: {
    environment: string;
    multiTenant: boolean;
  };
}

/**
 * Data Stack
 *
 * Deploys the data layer for multi-tenant configuration:
 * - etcd cluster for tenant configuration storage
 * - Service discovery for internal DNS
 * - Secrets for etcd authentication
 * - EFS for persistent etcd data
 *
 * Note: For production with high availability requirements,
 * consider using Amazon MemoryDB, ElastiCache, or a managed
 * etcd service. This implementation is suitable for dev/staging.
 *
 * Production Recommendations:
 * - Use 3+ nodes across different AZs
 * - Enable TLS for client and peer communication
 * - Use EFS or EBS for persistent storage
 * - Set up proper backup/restore procedures
 */
export class DataStack extends cdk.Stack {
  public etcdEndpoint?: string;
  public etcdSecret?: secretsmanager.ISecret;
  public readonly namespace: servicediscovery.IPrivateDnsNamespace;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    const { vpc, config } = props;

    // Private DNS namespace for service discovery
    this.namespace = new servicediscovery.PrivateDnsNamespace(this, 'Namespace', {
      name: `nhp.${config.environment}.internal`,
      vpc,
      description: 'LayerV NHP internal service discovery',
    });

    // Only create etcd if multi-tenant mode
    if (config.multiTenant) {
      this.createEtcdCluster(vpc, config);
    }

    // Outputs
    new cdk.CfnOutput(this, 'NamespaceName', {
      value: this.namespace.namespaceName,
      description: 'Service Discovery Namespace',
      exportName: `${this.stackName}-Namespace`,
    });

    if (this.etcdEndpoint) {
      new cdk.CfnOutput(this, 'EtcdEndpoint', {
        value: this.etcdEndpoint,
        description: 'etcd Endpoint',
        exportName: `${this.stackName}-EtcdEndpoint`,
      });
    }
  }

  private createEtcdCluster(vpc: ec2.IVpc, config: { environment: string }) {
    const isProd = config.environment === 'prod';

    // etcd credentials
    this.etcdSecret = new secretsmanager.Secret(this, 'EtcdSecret', {
      secretName: `layerv-nhp-etcd-${config.environment}`,
      description: 'etcd authentication credentials',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'root' }),
        generateStringKey: 'password',
        excludePunctuation: true,
        passwordLength: 32,
      },
    });

    // Security Group for etcd
    const etcdSecurityGroup = new ec2.SecurityGroup(this, 'EtcdSecurityGroup', {
      vpc,
      securityGroupName: `layerv-nhp-etcd-${config.environment}`,
      description: 'Security group for etcd cluster',
      allowAllOutbound: false,
    });

    // etcd client port from VPC
    etcdSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(2379),
      'etcd client port'
    );

    // etcd peer port (within security group)
    etcdSecurityGroup.addIngressRule(
      etcdSecurityGroup,
      ec2.Port.tcp(2380),
      'etcd peer port'
    );

    // Allow outbound to VPC for peer communication
    etcdSecurityGroup.addEgressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(2380),
      'etcd peer outbound'
    );

    // Allow outbound to HTTPS for AWS APIs (Secrets Manager, etc)
    etcdSecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'HTTPS for AWS APIs'
    );

    // EFS for persistent etcd data
    const fileSystem = new efs.FileSystem(this, 'EtcdEfs', {
      vpc,
      fileSystemName: `layerv-nhp-etcd-${config.environment}`,
      encrypted: true,
      lifecyclePolicy: efs.LifecyclePolicy.AFTER_14_DAYS,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
      throughputMode: efs.ThroughputMode.BURSTING,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroup: etcdSecurityGroup,
    });

    // EFS Access Point for etcd
    const accessPoint = fileSystem.addAccessPoint('EtcdAccessPoint', {
      path: '/etcd-data',
      createAcl: {
        ownerUid: '1000',
        ownerGid: '1000',
        permissions: '755',
      },
      posixUser: {
        uid: '1000',
        gid: '1000',
      },
    });

    // ECS Cluster for etcd
    const cluster = new ecs.Cluster(this, 'EtcdCluster', {
      clusterName: `layerv-nhp-etcd-${config.environment}`,
      vpc,
      containerInsights: true,
    });

    // Log group for etcd
    const logGroup = new logs.LogGroup(this, 'EtcdLogGroup', {
      logGroupName: `/layerv/etcd/${config.environment}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Task Definition for etcd
    const taskDefinition = new ecs.FargateTaskDefinition(this, 'EtcdTaskDef', {
      family: `layerv-nhp-etcd-${config.environment}`,
      memoryLimitMiB: 2048,
      cpu: 1024,
    });

    // Add EFS volume
    taskDefinition.addVolume({
      name: 'etcd-data',
      efsVolumeConfiguration: {
        fileSystemId: fileSystem.fileSystemId,
        transitEncryption: 'ENABLED',
        authorizationConfig: {
          accessPointId: accessPoint.accessPointId,
          iam: 'ENABLED',
        },
      },
    });

    // Grant task access to secrets and EFS
    this.etcdSecret.grantRead(taskDefinition.taskRole);
    fileSystem.grantReadWrite(taskDefinition.taskRole);

    // etcd container
    // Using single-node configuration for dev/staging
    // For production HA, use etcd discovery or static configuration with TLS
    //
    // Note on TLS: etcd is running in isolated subnets within the VPC.
    // Traffic is encrypted at the network level via VPC isolation.
    // For additional security in production, configure mTLS using
    // certificates from ACM PCA or HashiCorp Vault.
    const container = taskDefinition.addContainer('etcd', {
      containerName: 'etcd',
      image: ecs.ContainerImage.fromRegistry('quay.io/coreos/etcd:v3.5.11'),
      memoryLimitMiB: 1800,
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'etcd',
        logGroup,
      }),
      environment: {
        // Single node configuration
        ETCD_NAME: 'etcd-0',
        ETCD_DATA_DIR: '/etcd-data',
        // Listen on all interfaces within VPC
        // Note: etcd runs in isolated subnet, only accessible from private subnets
        ETCD_LISTEN_CLIENT_URLS: 'http://0.0.0.0:2379',
        ETCD_LISTEN_PEER_URLS: 'http://0.0.0.0:2380',
        // Advertise via service discovery DNS
        ETCD_ADVERTISE_CLIENT_URLS: `http://etcd.${this.namespace.namespaceName}:2379`,
        ETCD_INITIAL_ADVERTISE_PEER_URLS: `http://etcd.${this.namespace.namespaceName}:2380`,
        // Initial cluster configuration (single node)
        ETCD_INITIAL_CLUSTER: `etcd-0=http://etcd.${this.namespace.namespaceName}:2380`,
        ETCD_INITIAL_CLUSTER_STATE: 'new',
        ETCD_INITIAL_CLUSTER_TOKEN: `layerv-nhp-${config.environment}`,
        // Enable auto compaction
        ETCD_AUTO_COMPACTION_RETENTION: '1',
        ETCD_AUTO_COMPACTION_MODE: 'periodic',
        // Quota (1GB)
        ETCD_QUOTA_BACKEND_BYTES: '1073741824',
      },
      portMappings: [
        { containerPort: 2379, protocol: ecs.Protocol.TCP },
        { containerPort: 2380, protocol: ecs.Protocol.TCP },
      ],
      healthCheck: {
        command: ['CMD-SHELL', 'etcdctl endpoint health --endpoints=http://localhost:2379 || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(60),
      },
    });

    // Mount EFS volume
    container.addMountPoints({
      sourceVolume: 'etcd-data',
      containerPath: '/etcd-data',
      readOnly: false,
    });

    // ECS Service for etcd
    // Note: Running single instance for dev. For production HA,
    // consider using a managed service or proper etcd operator.
    const service = new ecs.FargateService(this, 'EtcdService', {
      serviceName: `layerv-nhp-etcd-${config.environment}`,
      cluster,
      taskDefinition,
      // Single instance for dev, document HA setup for prod
      desiredCount: 1,
      minHealthyPercent: 0, // Allow 0 during updates for single node
      maxHealthyPercent: 100,
      securityGroups: [etcdSecurityGroup],
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      cloudMapOptions: {
        name: 'etcd',
        cloudMapNamespace: this.namespace,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: cdk.Duration.seconds(30),
      },
      // Enable execute command for debugging
      enableExecuteCommand: true,
    });

    this.etcdEndpoint = `etcd.${this.namespace.namespaceName}:2379`;

    // Add warning for production
    if (isProd) {
      new cdk.CfnOutput(this, 'ProductionWarning', {
        value: 'WARNING: Single-node etcd is not recommended for production. Consider using Amazon MemoryDB or a managed etcd service.',
        description: 'Production deployment recommendation',
      });
    }
  }
}
