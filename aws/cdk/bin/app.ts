#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/network-stack';
import { ComputeStack } from '../lib/compute-stack';
import { DataStack } from '../lib/data-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { EcrStack } from '../lib/ecr-stack';
import { DnsStack } from '../lib/dns-stack';

/**
 * LayerV NHP Control Plane Infrastructure
 *
 * This CDK application deploys the LayerV-managed control plane:
 * - ECR repositories for container images
 * - VPC with public/private subnets across 3 AZs
 * - NHP Server instances behind Network Load Balancer
 * - etcd cluster for tenant configuration (multi-tenant mode)
 * - CloudWatch dashboards and alarms
 * - Route 53 DNS records
 */

const app = new cdk.App();

// Environment configuration
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID,
  region: process.env.CDK_DEFAULT_REGION || process.env.AWS_REGION || 'us-east-1',
};

// Configuration from context or environment
const config = {
  environment: app.node.tryGetContext('environment') || 'dev',
  domainName: app.node.tryGetContext('domainName') || 'nhp.layerv.ai',
  multiTenant: app.node.tryGetContext('multiTenant') !== 'false',
  minCapacity: parseInt(app.node.tryGetContext('minCapacity') || '2'),
  maxCapacity: parseInt(app.node.tryGetContext('maxCapacity') || '10'),
  // Optional: Route 53 hosted zone configuration
  hostedZoneId: app.node.tryGetContext('hostedZoneId'),
  hostedZoneName: app.node.tryGetContext('hostedZoneName'),
};

const stackPrefix = `LayerV-NHP-${config.environment}`;

// ECR Stack - Container registries (deploy first, persist across updates)
const ecrStack = new EcrStack(app, `LayerV-NHP-ECR`, {
  env,
  description: 'LayerV NHP - ECR Repositories',
  config,
});

// Network Stack - VPC, Subnets, NAT, etc.
const networkStack = new NetworkStack(app, `${stackPrefix}-Network`, {
  env,
  description: 'LayerV NHP Control Plane - Network Infrastructure',
  config,
});

// Data Stack - etcd, databases
const dataStack = new DataStack(app, `${stackPrefix}-Data`, {
  env,
  description: 'LayerV NHP Control Plane - Data Layer',
  vpc: networkStack.vpc,
  config,
});
dataStack.addDependency(networkStack);

// Compute Stack - NHP Servers, Load Balancer
const computeStack = new ComputeStack(app, `${stackPrefix}-Compute`, {
  env,
  description: 'LayerV NHP Control Plane - Compute Layer',
  vpc: networkStack.vpc,
  dataStack,
  serverRepo: ecrStack.serverRepo,
  config,
});
computeStack.addDependency(dataStack);
computeStack.addDependency(ecrStack);

// DNS Stack - Route 53 records (optional)
const dnsStack = new DnsStack(app, `${stackPrefix}-DNS`, {
  env,
  description: 'LayerV NHP Control Plane - DNS',
  nlb: computeStack.nlb,
  config,
});
dnsStack.addDependency(computeStack);

// Monitoring Stack - CloudWatch, Alarms
const monitoringStack = new MonitoringStack(app, `${stackPrefix}-Monitoring`, {
  env,
  description: 'LayerV NHP Control Plane - Monitoring',
  computeStack,
  config,
});
monitoringStack.addDependency(computeStack);

// Tags for all resources
cdk.Tags.of(app).add('Project', 'LayerV-NHP');
cdk.Tags.of(app).add('Environment', config.environment);
cdk.Tags.of(app).add('ManagedBy', 'CDK');

app.synth();
