import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Construct } from 'constructs';
import { ComputeStack } from './compute-stack';

export interface MonitoringStackProps extends cdk.StackProps {
  computeStack: ComputeStack;
  config: {
    environment: string;
    domainName: string;
  };
}

/**
 * Monitoring Stack
 *
 * Creates CloudWatch dashboards and alarms for NHP infrastructure:
 * - Main dashboard with key metrics
 * - Alarms for critical conditions
 * - SNS topic for notifications
 */
export class MonitoringStack extends cdk.Stack {
  public readonly alarmTopic: sns.ITopic;
  public readonly dashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: MonitoringStackProps) {
    super(scope, id, props);

    const { computeStack, config } = props;

    // SNS Topic for alarms
    this.alarmTopic = new sns.Topic(this, 'AlarmTopic', {
      topicName: `layerv-nhp-alarms-${config.environment}`,
      displayName: `LayerV NHP Alarms (${config.environment})`,
    });

    // CloudWatch Dashboard
    this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
      dashboardName: `LayerV-NHP-${config.environment}`,
    });

    // NLB Metrics - Extract load balancer name from ARN
    // ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/net/name/id
    const nlbArn = computeStack.nlb.loadBalancerArn;
    const nlbFullName = cdk.Fn.select(1, cdk.Fn.split(':loadbalancer/', nlbArn));
    const nlbMetrics = this.createNlbMetrics(nlbFullName);

    // ASG Metrics
    const asgMetrics = this.createAsgMetrics(computeStack.asg.autoScalingGroupName);

    // Dashboard Layout
    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: `# LayerV NHP Control Plane - ${config.environment}\n\nMonitoring dashboard for NHP Server infrastructure at ${config.domainName}`,
        width: 24,
        height: 1,
      })
    );

    // Row 1: NLB Traffic
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'NLB - Active Flows (UDP)',
        left: [nlbMetrics.activeFlowCount],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'NLB - Processed Bytes',
        left: [nlbMetrics.processedBytes],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'NLB - Target Health',
        left: [nlbMetrics.healthyHosts, nlbMetrics.unhealthyHosts],
        width: 8,
        height: 6,
      })
    );

    // Row 2: ASG Metrics
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'ASG - Instance Count',
        left: [asgMetrics.inServiceInstances, asgMetrics.desiredCapacity],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'ASG - CPU Utilization',
        left: [asgMetrics.cpuUtilization],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'ASG - Network Traffic',
        left: [asgMetrics.networkIn, asgMetrics.networkOut],
        width: 8,
        height: 6,
      })
    );

    // Row 3: NHP Protocol Metrics (custom metrics from server)
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'NHP - Knock Requests',
        left: [
          new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'KnockRequests',
            dimensionsMap: { Environment: config.environment },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'NHP - Auth Results',
        left: [
          new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'AuthSuccess',
            dimensionsMap: { Environment: config.environment },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          }),
          new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'AuthFailure',
            dimensionsMap: { Environment: config.environment },
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 8,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'NHP - Latency',
        left: [
          new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'KnockLatency',
            dimensionsMap: { Environment: config.environment },
            statistic: 'p99',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 8,
        height: 6,
      })
    );

    // Alarms
    this.createAlarms(nlbMetrics, asgMetrics, config);

    // Outputs
    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://${this.region}.console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.dashboard.dashboardName}`,
      description: 'CloudWatch Dashboard URL',
    });

    new cdk.CfnOutput(this, 'AlarmTopicArn', {
      value: this.alarmTopic.topicArn,
      description: 'SNS Topic ARN for alarms',
      exportName: `${this.stackName}-AlarmTopicArn`,
    });
  }

  private createNlbMetrics(nlbFullName: string) {
    return {
      activeFlowCount: new cloudwatch.Metric({
        namespace: 'AWS/NetworkELB',
        metricName: 'ActiveFlowCount',
        dimensionsMap: { LoadBalancer: nlbFullName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      processedBytes: new cloudwatch.Metric({
        namespace: 'AWS/NetworkELB',
        metricName: 'ProcessedBytes',
        dimensionsMap: { LoadBalancer: nlbFullName },
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
      healthyHosts: new cloudwatch.Metric({
        namespace: 'AWS/NetworkELB',
        metricName: 'HealthyHostCount',
        dimensionsMap: { LoadBalancer: nlbFullName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      unhealthyHosts: new cloudwatch.Metric({
        namespace: 'AWS/NetworkELB',
        metricName: 'UnHealthyHostCount',
        dimensionsMap: { LoadBalancer: nlbFullName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
    };
  }

  private createAsgMetrics(asgName: string) {
    return {
      inServiceInstances: new cloudwatch.Metric({
        namespace: 'AWS/AutoScaling',
        metricName: 'GroupInServiceInstances',
        dimensionsMap: { AutoScalingGroupName: asgName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      desiredCapacity: new cloudwatch.Metric({
        namespace: 'AWS/AutoScaling',
        metricName: 'GroupDesiredCapacity',
        dimensionsMap: { AutoScalingGroupName: asgName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      cpuUtilization: new cloudwatch.Metric({
        namespace: 'AWS/EC2',
        metricName: 'CPUUtilization',
        dimensionsMap: { AutoScalingGroupName: asgName },
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      networkIn: new cloudwatch.Metric({
        namespace: 'AWS/EC2',
        metricName: 'NetworkIn',
        dimensionsMap: { AutoScalingGroupName: asgName },
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
      networkOut: new cloudwatch.Metric({
        namespace: 'AWS/EC2',
        metricName: 'NetworkOut',
        dimensionsMap: { AutoScalingGroupName: asgName },
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
    };
  }

  private createAlarms(
    nlbMetrics: ReturnType<typeof this.createNlbMetrics>,
    asgMetrics: ReturnType<typeof this.createAsgMetrics>,
    config: { environment: string }
  ) {
    const alarmAction = new actions.SnsAction(this.alarmTopic);

    // High CPU Alarm
    const highCpuAlarm = new cloudwatch.Alarm(this, 'HighCpuAlarm', {
      alarmName: `layerv-nhp-high-cpu-${config.environment}`,
      alarmDescription: 'NHP Server CPU utilization is high',
      metric: asgMetrics.cpuUtilization,
      threshold: 80,
      evaluationPeriods: 3,
      datapointsToAlarm: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    highCpuAlarm.addAlarmAction(alarmAction);
    highCpuAlarm.addOkAction(alarmAction);

    // Unhealthy Hosts Alarm
    const unhealthyHostsAlarm = new cloudwatch.Alarm(this, 'UnhealthyHostsAlarm', {
      alarmName: `layerv-nhp-unhealthy-hosts-${config.environment}`,
      alarmDescription: 'NHP Server has unhealthy hosts',
      metric: nlbMetrics.unhealthyHosts,
      threshold: 1,
      evaluationPeriods: 2,
      datapointsToAlarm: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    unhealthyHostsAlarm.addAlarmAction(alarmAction);
    unhealthyHostsAlarm.addOkAction(alarmAction);

    // No Healthy Hosts Alarm (Critical)
    const noHealthyHostsAlarm = new cloudwatch.Alarm(this, 'NoHealthyHostsAlarm', {
      alarmName: `layerv-nhp-no-healthy-hosts-${config.environment}`,
      alarmDescription: 'CRITICAL: No healthy NHP Server hosts!',
      metric: nlbMetrics.healthyHosts,
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });
    noHealthyHostsAlarm.addAlarmAction(alarmAction);
    noHealthyHostsAlarm.addOkAction(alarmAction);

    // High Auth Failure Rate (custom metric)
    const authFailureAlarm = new cloudwatch.Alarm(this, 'AuthFailureAlarm', {
      alarmName: `layerv-nhp-auth-failures-${config.environment}`,
      alarmDescription: 'High rate of authentication failures',
      metric: new cloudwatch.MathExpression({
        expression: 'failures / (successes + failures) * 100',
        usingMetrics: {
          failures: new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'AuthFailure',
            dimensionsMap: { Environment: config.environment },
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
          successes: new cloudwatch.Metric({
            namespace: 'LayerV/NHP',
            metricName: 'AuthSuccess',
            dimensionsMap: { Environment: config.environment },
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
        },
        period: cdk.Duration.minutes(5),
      }),
      threshold: 20, // 20% failure rate
      evaluationPeriods: 3,
      datapointsToAlarm: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    authFailureAlarm.addAlarmAction(alarmAction);
    authFailureAlarm.addOkAction(alarmAction);

    // High Latency Alarm
    const highLatencyAlarm = new cloudwatch.Alarm(this, 'HighLatencyAlarm', {
      alarmName: `layerv-nhp-high-latency-${config.environment}`,
      alarmDescription: 'NHP knock latency is high',
      metric: new cloudwatch.Metric({
        namespace: 'LayerV/NHP',
        metricName: 'KnockLatency',
        dimensionsMap: { Environment: config.environment },
        statistic: 'p99',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 500, // 500ms p99
      evaluationPeriods: 3,
      datapointsToAlarm: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    highLatencyAlarm.addAlarmAction(alarmAction);
    highLatencyAlarm.addOkAction(alarmAction);
  }
}
