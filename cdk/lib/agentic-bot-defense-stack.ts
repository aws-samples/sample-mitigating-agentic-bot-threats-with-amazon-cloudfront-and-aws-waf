import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import { IdentityPool } from 'aws-cdk-lib/aws-cognito-identitypool';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as eventsources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as rekognition from 'aws-cdk-lib/aws-rekognition';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import { BotControlWebAcl } from './bot-control-web-acl';

/** Everything in this stack lives in us-east-1: CloudFront-scoped AWS WAF, Lambda@Edge, and Face Liveness. */
export const HOME_REGION = 'us-east-1';

export interface HumanVerificationSettings {
  /** Prefix for named resources. Lowercase letters, digits and hyphens. */
  readonly prefix: string;
  /** Pinned static version of the Bot Control managed rule group, for example "Version_7.0". */
  readonly botControlVersion: string;
  /** Minimum Face Liveness confidence (0-100) to treat the session as live. */
  readonly livenessConfidenceThreshold: number;
  /** Minimum SearchFacesByImage similarity (0-100) to treat two faces as the same person. */
  readonly faceMatchThreshold: number;
  /** Verified sessions one face may mint per window. */
  readonly maxVerificationsPerFace: number;
  /** Window length. Windows are fixed and aligned to the Unix epoch (24 hours resets at 00:00 UTC), not rolling. */
  readonly verificationWindowHours: number;
  /** Days a face vector is kept after its most recent verification. */
  readonly faceRetentionDays: number;
  /** Lifetime of the human-session cookie. */
  readonly humanSessionMinutes: number;
  readonly enableDemoTrigger: boolean;
}

export interface AgenticBotDefenseStackProps extends cdk.StackProps {
  readonly settings: HumanVerificationSettings;
  /** Directory containing the built challenge page (web/challenge/dist). */
  readonly challengePageAssetPath: string;
  /** Directory containing the demo site (web/site). */
  readonly siteAssetPath: string;
}

const LAMBDA_DIR = path.join(__dirname, '..', 'lambda');

export class AgenticBotDefenseStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AgenticBotDefenseStackProps) {
    super(scope, id, props);

    if (!cdk.Token.isUnresolved(this.region) && this.region !== HOME_REGION) {
      throw new Error(`This stack must be deployed to ${HOME_REGION}; got ${this.region}.`);
    }

    const { settings } = props;
    const names = {
      table: `${settings.prefix}-verification`,
      collection: `${settings.prefix}-verified-humans`,
      secret: `${settings.prefix}/session-signing-key`,
    };

    // ------------------------------------------------------------------
    // Detection: AWS WAF Bot Control (targeted) -> header for Lambda@Edge
    // ------------------------------------------------------------------
    const waf = new BotControlWebAcl(this, 'BotControl', {
      prefix: settings.prefix,
      botControlVersion: settings.botControlVersion,
      enableDemoTrigger: settings.enableDemoTrigger,
    });

    // ------------------------------------------------------------------
    // State: signing key, verification table, face collection
    // ------------------------------------------------------------------
    const signingKey = new secretsmanager.Secret(this, 'SessionSigningKey', {
      secretName: names.secret,
      description: 'HMAC key that signs the human-verification cookies',
      generateSecretString: { passwordLength: 64, excludePunctuation: true },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const table = new dynamodb.Table(this, 'VerificationTable', {
      tableName: names.table,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      stream: dynamodb.StreamViewType.KEYS_ONLY,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Deleting the collection on stack deletion deletes every stored face vector.
    const collection = new rekognition.CfnCollection(this, 'FaceCollection', {
      collectionId: names.collection,
    });
    collection.applyRemovalPolicy(cdk.RemovalPolicy.DESTROY);
    const collectionArn = this.formatArn({ service: 'rekognition', resource: 'collection', resourceName: names.collection });

    // ------------------------------------------------------------------
    // Browser credentials for streaming video to Face Liveness
    // ------------------------------------------------------------------
    // FaceLivenessDetector signs its StartFaceLivenessSession stream with
    // guest credentials from a Cognito identity pool. The guest role can do
    // nothing else: session creation and result retrieval stay server-side.
    const identityPool = new IdentityPool(this, 'LivenessIdentityPool', {
      identityPoolName: `${settings.prefix}-liveness`,
      allowUnauthenticatedIdentities: true,
    });
    identityPool.unauthenticatedRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['rekognition:StartFaceLivenessSession'],
      resources: ['*'],
    }));

    // ------------------------------------------------------------------
    // Response: Lambda@Edge
    // ------------------------------------------------------------------
    const edgeConfig = {
      region: HOME_REGION,
      secretId: names.secret,
      tableName: names.table,
      collectionId: names.collection,
      livenessConfidenceThreshold: settings.livenessConfidenceThreshold,
      faceMatchThreshold: settings.faceMatchThreshold,
      maxVerificationsPerFace: settings.maxVerificationsPerFace,
      verificationWindowHours: settings.verificationWindowHours,
      faceRetentionDays: settings.faceRetentionDays,
      humanSessionMinutes: settings.humanSessionMinutes,
      challengeTtlSeconds: 600,
      // A Face Liveness session ID expires 3 minutes after it is issued.
      livenessTtlSeconds: 240,
    };
    const edgeCode = edgeCodeWithConfig(path.join(LAMBDA_DIR, 'edge'), edgeConfig);

    const gateFunction = new cloudfront.experimental.EdgeFunction(this, 'GateFunction', {
      description: 'Viewer request: escalates WAF-flagged sessions to Face Liveness',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'gate.handler',
      code: edgeCode,
      memorySize: 128,
      timeout: cdk.Duration.seconds(5),
    });
    signingKey.grantRead(gateFunction);

    const livenessFunction = new cloudfront.experimental.EdgeFunction(this, 'LivenessFunction', {
      description: 'Origin request: Face Liveness session, verification, and sybil check',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'liveness.handler',
      code: edgeCode,
      memorySize: 512,
      timeout: cdk.Duration.seconds(30),
    });
    signingKey.grantRead(livenessFunction);
    table.grant(livenessFunction, 'dynamodb:PutItem', 'dynamodb:UpdateItem');
    livenessFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['rekognition:CreateFaceLivenessSession', 'rekognition:GetFaceLivenessSessionResults'],
      resources: ['*'],
    }));
    livenessFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['rekognition:SearchFacesByImage', 'rekognition:IndexFaces'],
      resources: [collectionArn],
    }));

    // ------------------------------------------------------------------
    // Retention: delete face vectors when their registry item goes away
    // ------------------------------------------------------------------
    const cleanupDlq = new sqs.Queue(this, 'FaceCleanupDlq', {
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
    });

    const cleanupFunction = new lambda.Function(this, 'FaceCleanupFunction', {
      description: 'Deletes expired face vectors from the Rekognition collection',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(LAMBDA_DIR, 'face-cleanup')),
      memorySize: 256,
      timeout: cdk.Duration.minutes(5),
      environment: { COLLECTION_ID: names.collection, TABLE_NAME: names.table },
      logGroup: new logs.LogGroup(this, 'FaceCleanupLogs', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });
    cleanupFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['rekognition:DeleteFaces', 'rekognition:ListFaces'],
      resources: [collectionArn],
    }));
    table.grant(cleanupFunction, 'dynamodb:BatchGetItem');
    cleanupFunction.addEventSource(new eventsources.DynamoEventSource(table, {
      startingPosition: lambda.StartingPosition.LATEST,
      batchSize: 100,
      retryAttempts: 5,
      bisectBatchOnError: true,
      onFailure: new eventsources.SqsDlq(cleanupDlq),
      filters: [lambda.FilterCriteria.filter({
        eventName: lambda.FilterRule.isEqual('REMOVE'),
        dynamodb: { Keys: { pk: { S: lambda.FilterRule.beginsWith('FACE#') } } },
      })],
    }));
    new events.Rule(this, 'DailyFaceSweep', {
      description: 'Deletes face vectors with no live registry item',
      schedule: events.Schedule.rate(cdk.Duration.days(1)),
      targets: [new targets.LambdaFunction(cleanupFunction, {
        event: events.RuleTargetInput.fromObject({ sweep: true }),
      })],
    });

    // ------------------------------------------------------------------
    // Content: demo site, challenge page, CloudFront
    // ------------------------------------------------------------------
    const siteBucket = privateBucket(this, 'SiteBucket');
    const challengeBucket = privateBucket(this, 'ChallengePageBucket');

    const siteHeaders = new cloudfront.ResponseHeadersPolicy(this, 'SiteHeaders', {
      comment: 'Security headers for the demo site',
      securityHeadersBehavior: commonSecurityHeaders(),
      customHeadersBehavior: {
        customHeaders: [{ header: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()', override: true }],
      },
    });

    // The challenge page needs: Cognito Identity (guest credentials), the
    // Rekognition streaming endpoint (WebSocket), and the Face Liveness CDN
    // that hosts the TensorFlow.js WASM binaries and face-detection model.
    const challengeCsp = [
      "default-src 'none'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      "font-src 'self' data:",
      "worker-src 'self' blob:",
      [
        "connect-src 'self'",
        `https://cognito-identity.${HOME_REGION}.amazonaws.com`,
        `https://streaming-rekognition.${HOME_REGION}.amazonaws.com`,
        `wss://streaming-rekognition.${HOME_REGION}.amazonaws.com`,
        'https://cdn.liveness.rekognition.amazonaws.com',
      ].join(' '),
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'none'",
    ].join('; ');

    const challengeHeaders = new cloudfront.ResponseHeadersPolicy(this, 'ChallengePageHeaders', {
      comment: 'Security headers for the Face Liveness challenge page',
      securityHeadersBehavior: {
        ...commonSecurityHeaders(),
        contentSecurityPolicy: { contentSecurityPolicy: challengeCsp, override: true },
      },
      customHeadersBehavior: {
        customHeaders: [{ header: 'Permissions-Policy', value: 'camera=(self), microphone=(), geolocation=()', override: true }],
      },
    });

    const siteOrigin = origins.S3BucketOrigin.withOriginAccessControl(siteBucket);
    const challengeOrigin = origins.S3BucketOrigin.withOriginAccessControl(challengeBucket);

    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      comment: `${settings.prefix}: Bot Control + Face Liveness step-up`,
      defaultRootObject: 'index.html',
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      // With the default *.cloudfront.net certificate the TLS policy is fixed.
      // For production, add a custom domain + ACM certificate and set
      // minimumProtocolVersion to TLS_V1_2_2021.
      webAclId: waf.webAcl.attrArn,
      defaultBehavior: {
        origin: siteOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: siteHeaders,
        // Viewer request runs after AWS WAF and before the cache, so cached
        // content is gated as well.
        edgeLambdas: [{ functionVersion: gateFunction.currentVersion, eventType: cloudfront.LambdaEdgeEventType.VIEWER_REQUEST }],
      },
      additionalBehaviors: {
        '/challenge/*': {
          origin: challengeOrigin,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
          cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
          responseHeadersPolicy: challengeHeaders,
        },
        '/liveness/*': {
          // The origin-request function answers every request; nothing is
          // forwarded to the bucket.
          origin: siteOrigin,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          // Forwards cookies and Sec-Fetch-* headers to the origin-request event.
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          edgeLambdas: [{ functionVersion: livenessFunction.currentVersion, eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST }],
        },
      },
    });

    new s3deploy.BucketDeployment(this, 'DeploySite', {
      sources: [s3deploy.Source.asset(props.siteAssetPath)],
      destinationBucket: siteBucket,
      distribution,
      distributionPaths: ['/*'],
    });

    new s3deploy.BucketDeployment(this, 'DeployChallengePage', {
      sources: [
        s3deploy.Source.asset(props.challengePageAssetPath),
        // Runtime config, resolved at deploy time.
        s3deploy.Source.jsonData('config.json', {
          region: HOME_REGION,
          identityPoolId: identityPool.identityPoolId,
          faceRetentionDays: settings.faceRetentionDays,
        }),
      ],
      destinationBucket: challengeBucket,
      destinationKeyPrefix: 'challenge/',
      distribution,
      distributionPaths: ['/challenge/*'],
    });

    new cdk.CfnOutput(this, 'DistributionUrl', { value: `https://${distribution.distributionDomainName}` });
    new cdk.CfnOutput(this, 'DemoTriggerUrl', {
      value: settings.enableDemoTrigger ? `https://${distribution.distributionDomainName}/?simulate-agent=1` : 'disabled',
    });
    new cdk.CfnOutput(this, 'FaceCollectionId', { value: names.collection });
    new cdk.CfnOutput(this, 'WebAclName', { value: waf.webAcl.name! });

    this.acknowledgeNagFindings({
      functions: [gateFunction, livenessFunction, cleanupFunction],
      guestRole: identityPool.unauthenticatedRole,
      livenessFunction,
      cleanupFunction,
      deployedBuckets: [siteBucket, challengeBucket],
    });
  }

  /**
   * cdk-nag (v3) acknowledgements, each scoped as narrowly as the finding allows
   * and with the reason it is acceptable.
   */
  private acknowledgeNagFindings(scoped: {
    functions: Construct[];
    guestRole: Construct;
    livenessFunction: Construct;
    cleanupFunction: Construct;
    deployedBuckets: s3.Bucket[];
  }): void {
    const ack = (scope: Construct, id: string, reason: string) => cdk.Validations.of(scope).acknowledge({ id, reason });

    const stackWide: Array<[string, string]> = [
      ['AwsSolutions-L1', 'Lambda functions pin Node.js 22, which Lambda@Edge supports; CDK-managed custom resources choose their own runtime.'],
      ['AwsSolutions-S1', 'Sample: buckets hold static assets only. Enable server access logging for production.'],
      ['AwsSolutions-CFR1', 'Sample: no geo restriction is required for the demo.'],
      ['AwsSolutions-CFR3', 'Sample: enable CloudFront standard logging for production. AWS WAF logs every request.'],
      ['AwsSolutions-CFR4', 'Sample uses the default *.cloudfront.net certificate. Use a custom domain with ACM and TLSv1.2_2021 in production.'],
      ['AwsSolutions-SMG4', 'Sample: the signing key is not rotated automatically. See README for a rotation approach.'],
      ['AwsSolutions-COG7', 'Guest identities are required: FaceLivenessDetector signs StartFaceLivenessSession with guest credentials. The guest role allows only that action.'],
      ['AwsSolutions-SQS3', 'This queue is itself the dead-letter queue for the face-cleanup event source.'],
    ];
    for (const [id, reason] of stackWide) ack(this, id, reason);

    const basicExecution = 'AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]';
    for (const fn of scoped.functions) ack(fn, basicExecution, 'AWSLambdaBasicExecutionRole grants CloudWatch Logs write access only.');

    const anyResource = 'AwsSolutions-IAM5[Resource::*]';
    ack(scoped.guestRole, anyResource, 'rekognition:StartFaceLivenessSession does not support resource-level permissions.');
    ack(scoped.livenessFunction, anyResource, 'CreateFaceLivenessSession and GetFaceLivenessSessionResults do not support resource-level permissions.');
    ack(scoped.cleanupFunction, anyResource, 'dynamodb:ListStreams, added by the DynamoDB event source, does not support resource-level permissions.');

    // The BucketDeployment provider is a CDK-managed singleton at stack scope.
    const provider = this.node.children.find((c) => c.node.id.startsWith('Custom::CDKBucketDeployment'));
    if (provider) {
      const account = cdk.Token.isUnresolved(this.account) ? '<AWS::AccountId>' : this.account;
      const qualifier = this.node.tryGetContext(cdk.BOOTSTRAP_QUALIFIER_CONTEXT) ?? cdk.DefaultStackSynthesizer.DEFAULT_QUALIFIER;
      const findings = [
        basicExecution,
        anyResource,
        ...['s3:GetObject*', 's3:GetBucket*', 's3:List*', 's3:DeleteObject*', 's3:Abort*'].map((a) => `AwsSolutions-IAM5[Action::${a}]`),
        `AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:s3:::cdk-${qualifier}-assets-${account}-${this.region}/*]`,
        ...scoped.deployedBuckets.map((b) => `AwsSolutions-IAM5[Resource::<${this.getLogicalId(b.node.defaultChild as cdk.CfnElement)}.Arn>/*]`),
      ];
      for (const id of findings) ack(provider, id, 'Permissions generated by the CDK-managed BucketDeployment provider.');
    }
  }
}

function privateBucket(scope: Construct, id: string): s3.Bucket {
  return new s3.Bucket(scope, id, {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED,
    enforceSSL: true,
    objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
    removalPolicy: cdk.RemovalPolicy.DESTROY,
    autoDeleteObjects: true,
  });
}

function commonSecurityHeaders(): cloudfront.ResponseSecurityHeadersBehavior {
  return {
    contentTypeOptions: { override: true },
    frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
    referrerPolicy: { referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: true },
    strictTransportSecurity: { accessControlMaxAge: cdk.Duration.days(730), includeSubdomains: true, override: true },
  };
}

/**
 * Lambda@Edge does not support environment variables, so the configuration is
 * written into the deployment package as config.json at synth time. Only
 * literal, non-secret values are allowed.
 */
function edgeCodeWithConfig(sourceDir: string, config: Record<string, string | number>): lambda.Code {
  for (const [key, value] of Object.entries(config)) {
    if (cdk.Token.isUnresolved(value)) {
      throw new Error(`Lambda@Edge config value "${key}" must be known at synth time.`);
    }
  }
  return lambda.Code.fromAsset(sourceDir, {
    assetHashType: cdk.AssetHashType.OUTPUT,
    bundling: {
      // Only used if local bundling is unavailable.
      image: cdk.DockerImage.fromRegistry('public.ecr.aws/docker/library/node:22-alpine'),
      local: {
        tryBundle(outputDir: string): boolean {
          fs.cpSync(sourceDir, outputDir, {
            recursive: true,
            filter: (src) => path.basename(src) !== 'config.json',
          });
          fs.writeFileSync(path.join(outputDir, 'config.json'), `${JSON.stringify(config, null, 2)}\n`);
          return true;
        },
      },
    },
  });
}
