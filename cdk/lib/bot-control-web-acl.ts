import * as cdk from 'aws-cdk-lib';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

/** Header name AWS WAF inserts. It reaches Lambda@Edge as "x-amzn-waf-bot-suspect". */
export const SUSPECT_HEADER_NAME = 'bot-suspect';

/**
 * Header carrying the AWS WAF token's client session identifier. It reaches
 * Lambda@Edge as "x-amzn-waf-token-id". The human-session cookie is bound to
 * this value, so reusing the cookie means reusing the AWS WAF token, which
 * Bot Control's token-reuse rules track.
 */
export const TOKEN_ID_HEADER_NAME = 'token-id';

/**
 * AWS WAF token management adds "awswaf:managed:token:id:<identifier>" to
 * requests evaluated by Bot Control. Dynamic label interpolation resolves the
 * namespace to the identifier.
 */
const TOKEN_ID_LABEL_NAMESPACE = 'awswaf:managed:token:id:';

/**
 * Bot Control rules whose signals point at automation running inside a real
 * browser. Their actions are overridden to Count so the rule group only
 * labels the request; the FlagSuspectedBrowserAgents rule then turns those
 * labels into a header, and Lambda@Edge escalates to Face Liveness.
 *
 * Rules not listed keep their managed actions. Clear-cut traffic (non-browser
 * user agents, TGT_VolumetricSessionMaximum, TGT_TokenReuseIpHigh, and so on)
 * is still blocked by Bot Control directly.
 *
 * A flagged request that carries a valid human-session cookie bound to the
 * same AWS WAF token passes the gate. Token reuse below Bot Control's High
 * thresholds (for example TGT_TokenReuseIpMedium) therefore doesn't force a
 * new Face Liveness check; the High rules block it.
 */
export const ESCALATE_TO_LIVENESS_RULES = [
  'SignalAutomatedBrowser',
  'TGT_SignalAutomatedBrowser',
  'TGT_SignalBrowserAutomationExtension',
  'TGT_SignalBrowserInconsistency',
  'TGT_VolumetricSession',
  'TGT_TokenReuseIpMedium',
  'TGT_ML_CoordinatedActivityMedium',
  'TGT_ML_CoordinatedActivityHigh',
] as const;

const BOT_CONTROL_LABEL_PREFIX = 'awswaf:managed:aws:bot-control:';

export interface BotControlWebAclProps {
  readonly prefix: string;
  /**
   * Static version of AWSManagedRulesBotControlRuleSet, for example "Version_7.0".
   * Pinned on purpose: without a version, AWS WAF uses the rule group's default
   * version, which can lack rules listed in ESCALATE_TO_LIVENESS_RULES. AWS WAF
   * accepts overrides for rules that don't exist, so a missing rule fails silently.
   */
  readonly botControlVersion: string;
  /**
   * Add a rule that flags any request carrying "?simulate-agent=1", so the
   * Face Liveness flow can be exercised from an ordinary browser. Disable
   * outside of demos.
   */
  readonly enableDemoTrigger: boolean;
}

const visibility = (metricName: string): wafv2.CfnWebACL.VisibilityConfigProperty => ({
  cloudWatchMetricsEnabled: true,
  sampledRequestsEnabled: true,
  metricName,
});

/**
 * Path prefix match on the normalized path. CloudFront normalizes the path
 * (RFC 3986) before it picks a cache behavior, so matching the raw path would
 * let "/challenge/../checkout.html" fall outside Bot Control's scope here and
 * still reach the default behavior.
 */
const uriStartsWith = (path: string): wafv2.CfnWebACL.StatementProperty => ({
  byteMatchStatement: {
    fieldToMatch: { uriPath: {} },
    positionalConstraint: 'STARTS_WITH',
    searchString: path,
    textTransformations: [
      { priority: 0, type: 'URL_DECODE' },
      { priority: 1, type: 'NORMALIZE_PATH' },
    ],
  },
});

const insertSuspectHeader: wafv2.CfnWebACL.RuleActionProperty = {
  count: {
    customRequestHandling: {
      insertHeaders: [{ name: SUSPECT_HEADER_NAME, value: 'true' }],
    },
  },
};

/**
 * CloudFront-scoped web ACL (must be created in us-east-1).
 *
 * Rule order:
 *   0  BlockSpoofedWafHeaders      block client-supplied "x-amzn-waf-*" headers
 *   1  RateLimitLivenessApi        cap Face Liveness attempts per IP
 *   10 AWS-BotControl              targeted Bot Control, escalation rules -> Count
 *   15 AcquireWafToken             silent Challenge for token-less page loads
 *   20 FlagSuspectedBrowserAgents  labels -> "x-amzn-waf-bot-suspect: true"
 *   25 ForwardWafTokenId           token ID label -> "x-amzn-waf-token-id"
 *   30 DemoTrigger (optional)      "?simulate-agent=1" -> same header as rule 20
 */
export class BotControlWebAcl extends Construct {
  public readonly webAcl: wafv2.CfnWebACL;
  public readonly logGroup: logs.LogGroup;

  constructor(scope: Construct, id: string, props: BotControlWebAclProps) {
    super(scope, id);

    // The challenge page is outside Bot Control's scope: it is only reached
    // after a flag. The liveness API stays in scope, because AWS WAF only adds
    // the token ID label to requests that Bot Control evaluates, and the API
    // binds each cookie to that ID. It is also rate limited by rule 1.
    const outsideChallengePage: wafv2.CfnWebACL.StatementProperty = {
      notStatement: { statement: uriStartsWith('/challenge/') },
    };

    const rules: wafv2.CfnWebACL.RuleProperty[] = [
      {
        // AWS WAF overwrites a header it inserts, but blocking any client-sent
        // "x-amzn-waf-" header keeps downstream logic unambiguous.
        name: 'BlockSpoofedWafHeaders',
        priority: 0,
        action: { block: {} },
        statement: {
          byteMatchStatement: {
            fieldToMatch: { headers: { matchPattern: { all: {} }, matchScope: 'KEY', oversizeHandling: 'MATCH' } },
            positionalConstraint: 'STARTS_WITH',
            searchString: 'x-amzn-waf-',
            textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
          },
        },
        visibilityConfig: visibility('BlockSpoofedWafHeaders'),
      },
      {
        // Each attempt is two calls (session + verify), so 10 requests in 5
        // minutes is about 5 attempts, in line with the Rekognition guidance to
        // allow about five failed checks in a few minutes per device.
        name: 'RateLimitLivenessApi',
        priority: 1,
        action: { block: {} },
        statement: {
          rateBasedStatement: {
            limit: 10,
            evaluationWindowSec: 300,
            aggregateKeyType: 'IP',
            scopeDownStatement: uriStartsWith('/liveness/'),
          },
        },
        visibilityConfig: visibility('RateLimitLivenessApi'),
      },
      {
        name: 'AWS-BotControl',
        priority: 10,
        overrideAction: { none: {} },
        statement: {
          managedRuleGroupStatement: {
            vendorName: 'AWS',
            name: 'AWSManagedRulesBotControlRuleSet',
            version: props.botControlVersion,
            managedRuleGroupConfigs: [
              { awsManagedRulesBotControlRuleSet: { inspectionLevel: 'TARGETED', enableMachineLearning: true } },
            ],
            ruleActionOverrides: ESCALATE_TO_LIVENESS_RULES.map((name) => ({ name, actionToUse: { count: {} } })),
            scopeDownStatement: outsideChallengePage,
          },
        },
        visibilityConfig: visibility('AWS-BotControl'),
      },
      {
        // The targeted rules inspect the AWS WAF token. A silent Challenge on the
        // first HTML page load gives every real browser a token. Verified bots
        // (search engines and similar) are left alone. For SPAs and mobile apps,
        // use the AWS WAF client application integration SDKs instead.
        name: 'AcquireWafToken',
        priority: 15,
        action: { challenge: {} },
        statement: {
          andStatement: {
            statements: [
              { labelMatchStatement: { scope: 'LABEL', key: 'awswaf:managed:token:absent' } },
              {
                notStatement: {
                  statement: { labelMatchStatement: { scope: 'LABEL', key: `${BOT_CONTROL_LABEL_PREFIX}bot:verified` } },
                },
              },
              {
                byteMatchStatement: {
                  fieldToMatch: { method: {} },
                  positionalConstraint: 'EXACTLY',
                  searchString: 'GET',
                  textTransformations: [{ priority: 0, type: 'NONE' }],
                },
              },
              {
                byteMatchStatement: {
                  fieldToMatch: { singleHeader: { Name: 'accept' } },
                  positionalConstraint: 'CONTAINS',
                  searchString: 'text/html',
                  textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                },
              },
            ],
          },
        },
        visibilityConfig: visibility('AcquireWafToken'),
      },
      {
        name: 'FlagSuspectedBrowserAgents',
        priority: 20,
        action: insertSuspectHeader,
        statement: {
          orStatement: {
            statements: ESCALATE_TO_LIVENESS_RULES.map((rule) => ({
              labelMatchStatement: { scope: 'LABEL', key: `${BOT_CONTROL_LABEL_PREFIX}${rule}` },
            })),
          },
        },
        visibilityConfig: visibility('FlagSuspectedBrowserAgents'),
      },
      {
        // Forward the AWS WAF token's session ID so Lambda@Edge can bind its
        // cookies to it. Clients can't forge the header: rule 0 blocks any
        // client-sent "x-amzn-waf-" header, and AWS WAF inserts headers only
        // after evaluation completes.
        name: 'ForwardWafTokenId',
        priority: 25,
        action: {
          count: {
            customRequestHandling: {
              insertHeaders: [{ name: TOKEN_ID_HEADER_NAME, value: `\${${TOKEN_ID_LABEL_NAMESPACE}}` }],
            },
          },
        },
        statement: { labelMatchStatement: { scope: 'NAMESPACE', key: TOKEN_ID_LABEL_NAMESPACE } },
        visibilityConfig: visibility('ForwardWafTokenId'),
      },
    ];

    if (props.enableDemoTrigger) {
      rules.push({
        name: 'DemoTrigger',
        priority: 30,
        action: insertSuspectHeader,
        statement: {
          byteMatchStatement: {
            fieldToMatch: { singleQueryArgument: { Name: 'simulate-agent' } },
            positionalConstraint: 'EXACTLY',
            searchString: '1',
            textTransformations: [{ priority: 0, type: 'NONE' }],
          },
        },
        visibilityConfig: visibility('DemoTrigger'),
      });
    }

    this.webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: `${props.prefix}-web-acl`,
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      rules,
      visibilityConfig: visibility(`${props.prefix}-web-acl`),
    });

    // Log group names for AWS WAF must start with "aws-waf-logs-".
    this.logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `aws-waf-logs-${props.prefix}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new wafv2.CfnLoggingConfiguration(this, 'Logging', {
      resourceArn: this.webAcl.attrArn,
      logDestinationConfigs: [this.logGroup.logGroupArn],
      // Session cookies are bearer credentials; keep them out of the logs.
      redactedFields: [{ singleHeader: { Name: 'cookie' } }],
    });
  }
}
