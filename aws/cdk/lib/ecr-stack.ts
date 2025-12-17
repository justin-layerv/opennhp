import * as cdk from 'aws-cdk-lib';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface EcrStackProps extends cdk.StackProps {
  config: {
    environment: string;
  };
  githubOrg?: string;
  githubRepo?: string;
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
  public readonly githubActionsRole: iam.IRole;

  constructor(scope: Construct, id: string, props: EcrStackProps) {
    super(scope, id, props);

    const { config, githubOrg = 'layervai', githubRepo = 'nhp' } = props;

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

    // GitHub Actions OIDC provider (already exists in account)
    const githubOidcProvider = iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(
      this,
      'GitHubOidcProvider',
      `arn:aws:iam::${this.account}:oidc-provider/token.actions.githubusercontent.com`
    );

    // GitHub Actions role for CI/CD
    this.githubActionsRole = new iam.Role(this, 'GitHubActionsRole', {
      roleName: 'nhp-github-actions',
      description: `GitHub Actions role for ${githubOrg}/${githubRepo}`,
      assumedBy: new iam.FederatedPrincipal(
        githubOidcProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          },
          StringLike: {
            'token.actions.githubusercontent.com:sub': `repo:${githubOrg}/${githubRepo}:*`,
          },
        },
        'sts:AssumeRoleWithWebIdentity'
      ),
      inlinePolicies: {
        'ecr-push': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              sid: 'ECRAuth',
              effect: iam.Effect.ALLOW,
              actions: ['ecr:GetAuthorizationToken'],
              resources: ['*'],
            }),
            new iam.PolicyStatement({
              sid: 'ECRPush',
              effect: iam.Effect.ALLOW,
              actions: [
                'ecr:BatchCheckLayerAvailability',
                'ecr:GetDownloadUrlForLayer',
                'ecr:BatchGetImage',
                'ecr:PutImage',
                'ecr:InitiateLayerUpload',
                'ecr:UploadLayerPart',
                'ecr:CompleteLayerUpload',
                'ecr:DescribeRepositories',
                'ecr:DescribeImages',
              ],
              resources: [
                this.serverRepo.repositoryArn,
                this.acRepo.repositoryArn,
              ],
            }),
          ],
        }),
        'cdk-deploy': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              sid: 'CDKAssumeRole',
              effect: iam.Effect.ALLOW,
              actions: ['sts:AssumeRole'],
              resources: [`arn:aws:iam::${this.account}:role/cdk-*`],
            }),
          ],
        }),
      },
    });

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

    new cdk.CfnOutput(this, 'GitHubActionsRoleArn', {
      value: this.githubActionsRole.roleArn,
      description: 'GitHub Actions Role ARN (add to GitHub secrets as AWS_ROLE_ARN)',
      exportName: `${this.stackName}-GitHubActionsRoleArn`,
    });
  }
}
