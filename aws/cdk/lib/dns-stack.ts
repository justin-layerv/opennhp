import * as cdk from 'aws-cdk-lib';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53targets from 'aws-cdk-lib/aws-route53-targets';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import { Construct } from 'constructs';

export interface DnsStackProps extends cdk.StackProps {
  nlb: elbv2.INetworkLoadBalancer;
  config: {
    environment: string;
    domainName: string;
    hostedZoneId?: string;
    hostedZoneName?: string;
  };
}

/**
 * DNS Stack
 *
 * Creates Route 53 DNS records for the NHP Server.
 * Requires an existing hosted zone or creates one.
 */
export class DnsStack extends cdk.Stack {
  public readonly hostedZone?: route53.IHostedZone;

  constructor(scope: Construct, id: string, props: DnsStackProps) {
    super(scope, id, props);

    const { nlb, config } = props;

    // Parse domain name
    const domainParts = config.domainName.split('.');
    const subdomain = domainParts[0]; // e.g., "nhp"
    const rootDomain = domainParts.slice(1).join('.'); // e.g., "layerv.ai"

    // Look up existing hosted zone or skip if not configured
    if (config.hostedZoneId && config.hostedZoneName) {
      this.hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
        hostedZoneId: config.hostedZoneId,
        zoneName: config.hostedZoneName,
      });

      // Create A record pointing to NLB
      new route53.ARecord(this, 'NhpARecord', {
        zone: this.hostedZone,
        recordName: subdomain,
        target: route53.RecordTarget.fromAlias(
          new route53targets.LoadBalancerTarget(nlb)
        ),
        ttl: cdk.Duration.minutes(5),
        comment: `NHP Server endpoint (${config.environment})`,
      });

      // Create AAAA record if NLB supports IPv6
      // Note: NLB must be dualstack enabled for this to work
      // Skipping for now as it requires NLB dualstack configuration

      new cdk.CfnOutput(this, 'DnsEndpoint', {
        value: config.domainName,
        description: 'NHP Server DNS endpoint',
        exportName: `${this.stackName}-DnsEndpoint`,
      });
    } else {
      // Output instructions for manual DNS setup
      new cdk.CfnOutput(this, 'ManualDnsSetup', {
        value: `Create CNAME or ALIAS record: ${config.domainName} -> ${nlb.loadBalancerDnsName}`,
        description: 'Manual DNS setup instructions',
      });
    }

    // Output NLB DNS for reference
    new cdk.CfnOutput(this, 'NlbDnsName', {
      value: nlb.loadBalancerDnsName,
      description: 'NLB DNS Name (for manual DNS configuration)',
    });
  }
}
