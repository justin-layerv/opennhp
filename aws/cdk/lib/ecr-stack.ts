import * as cdk from 'aws-cdk-lib';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface EcrStackProps extends cdk.StackProps {
  config: {
    environment: string;
  };
}

/**
 * ECR Stack
 *
 * Creates ECR repositories for NHP container images.
 * These are created in a separate stack so they persist
 * across compute stack updates.
 *
 * The AC repository has a cross-account pull policy allowing
 * any authenticated AWS account to pull images (for customer deployments).
 */
export class EcrStack extends cdk.Stack {
  public readonly serverRepo: ecr.IRepository;
  public readonly acRepo: ecr.IRepository;

  constructor(scope: Construct, id: string, props: EcrStackProps) {
    super(scope, id, props);

    const { config } = props;

    // NHP Server repository (internal use only)
    this.serverRepo = new ecr.Repository(this, 'ServerRepo', {
      repositoryName: `layerv/nhp-server`,
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.MUTABLE,
      lifecycleRules: [
        {
          description: 'Keep last 10 images',
          maxImageCount: 10,
          rulePriority: 1,
          tagStatus: ecr.TagStatus.ANY,
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // NHP AC repository (for customer deployments)
    this.acRepo = new ecr.Repository(this, 'AcRepo', {
      repositoryName: `layerv/nhp-ac`,
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.MUTABLE,
      lifecycleRules: [
        {
          description: 'Keep last 10 images',
          maxImageCount: 10,
          rulePriority: 1,
          tagStatus: ecr.TagStatus.ANY,
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Allow any authenticated AWS account to pull AC images
    // This enables customer CloudFormation deployments to pull from our ECR
    this.acRepo.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCrossAccountPull',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      actions: [
        'ecr:GetDownloadUrlForLayer',
        'ecr:BatchGetImage',
        'ecr:BatchCheckLayerAvailability',
      ],
      conditions: {
        StringEquals: {
          'aws:PrincipalType': 'AssumedRole',
        },
      },
    }));

    // Outputs
    new cdk.CfnOutput(this, 'ServerRepoUri', {
      value: this.serverRepo.repositoryUri,
      description: 'NHP Server ECR Repository URI',
      exportName: `${this.stackName}-ServerRepoUri`,
    });

    new cdk.CfnOutput(this, 'AcRepoUri', {
      value: this.acRepo.repositoryUri,
      description: 'NHP AC ECR Repository URI',
      exportName: `${this.stackName}-AcRepoUri`,
    });
  }
}
