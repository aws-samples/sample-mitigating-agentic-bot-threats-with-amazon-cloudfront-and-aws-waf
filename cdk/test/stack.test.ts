import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AgenticBotDefenseStack, HumanVerificationSettings } from '../lib/agentic-bot-defense-stack';
import { ESCALATE_TO_LIVENESS_RULES } from '../lib/bot-control-web-acl';

const SETTINGS: HumanVerificationSettings = {
  prefix: 'test-bot-defense',
  botControlVersion: 'Version_7.0',
  livenessConfidenceThreshold: 90,
  faceMatchThreshold: 95,
  maxVerificationsPerFace: 5,
  verificationWindowHours: 24,
  faceRetentionDays: 30,
  humanSessionMinutes: 15,
  enableDemoTrigger: true,
};

function synth(overrides: Partial<HumanVerificationSettings> = {}) {
  const challengeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'challenge-'));
  fs.writeFileSync(path.join(challengeDir, 'index.html'), '<!doctype html>');
  const app = new cdk.App();
  const stack = new AgenticBotDefenseStack(app, 'TestStack', {
    env: { account: '111111111111', region: 'us-east-1' },
    settings: { ...SETTINGS, ...overrides },
    challengePageAssetPath: challengeDir,
    siteAssetPath: path.join(__dirname, '..', '..', 'web', 'site'),
  });
  const template = Template.fromStack(stack);
  return { app, stack, template };
}

const { app, stack, template } = synth();

test('web ACL rules run in the documented order', () => {
  const [acl] = Object.values(template.findResources('AWS::WAFv2::WebACL')) as any[];
  const rules = acl.Properties.Rules.map((r: any) => [r.Priority, r.Name]);
  assert.deepEqual(rules, [
    [0, 'BlockSpoofedWafHeaders'],
    [1, 'RateLimitLivenessApi'],
    [10, 'AWS-BotControl'],
    [15, 'AcquireWafToken'],
    [20, 'FlagSuspectedBrowserAgents'],
    [25, 'ForwardWafTokenId'],
    [30, 'DemoTrigger'],
  ]);
  assert.equal(acl.Properties.Scope, 'CLOUDFRONT');
});

test('the AWS WAF token ID is forwarded by label interpolation, after Bot Control adds the label', () => {
  const [acl] = Object.values(template.findResources('AWS::WAFv2::WebACL')) as any[];
  const forward = acl.Properties.Rules.find((r: any) => r.Name === 'ForwardWafTokenId');
  assert.deepEqual(forward.Statement, { LabelMatchStatement: { Scope: 'NAMESPACE', Key: 'awswaf:managed:token:id:' } });
  assert.deepEqual(forward.Action, {
    Count: { CustomRequestHandling: { InsertHeaders: [{ Name: 'token-id', Value: '${awswaf:managed:token:id:}' }] } },
  });
  const botControl = acl.Properties.Rules.find((r: any) => r.Name === 'AWS-BotControl');
  assert.ok(forward.Priority > botControl.Priority);
});

test('Bot Control evaluates the liveness API (needed for the token ID) but not the challenge page', () => {
  const [acl] = Object.values(template.findResources('AWS::WAFv2::WebACL')) as any[];
  const botControl = acl.Properties.Rules.find((r: any) => r.Name === 'AWS-BotControl');
  const scopeDown = botControl.Statement.ManagedRuleGroupStatement.ScopeDownStatement;
  assert.equal(scopeDown.NotStatement.Statement.ByteMatchStatement.SearchString, '/challenge/');
  assert.doesNotMatch(JSON.stringify(scopeDown), /\/liveness\//);
});

test('path scope-downs match the normalized path, as CloudFront does when it picks a cache behavior', () => {
  const [acl] = Object.values(template.findResources('AWS::WAFv2::WebACL')) as any[];
  const rules = Object.fromEntries(acl.Properties.Rules.map((r: any) => [r.Name, r]));
  const pathMatches = [
    rules['AWS-BotControl'].Statement.ManagedRuleGroupStatement.ScopeDownStatement.NotStatement.Statement.ByteMatchStatement,
    rules.RateLimitLivenessApi.Statement.RateBasedStatement.ScopeDownStatement.ByteMatchStatement,
  ];
  for (const match of pathMatches) {
    assert.deepEqual(match.FieldToMatch, { UriPath: {} });
    assert.deepEqual(match.TextTransformations, [
      { Priority: 0, Type: 'URL_DECODE' },
      { Priority: 1, Type: 'NORMALIZE_PATH' },
    ]);
  }
});

test('Bot Control runs at the targeted level and only counts the escalation rules', () => {
  template.hasResourceProperties('AWS::WAFv2::WebACL', {
    Rules: Match.arrayWith([Match.objectLike({
      Name: 'AWS-BotControl',
      OverrideAction: { None: {} },
      Statement: {
        ManagedRuleGroupStatement: Match.objectLike({
          Name: 'AWSManagedRulesBotControlRuleSet',
          ManagedRuleGroupConfigs: [{ AWSManagedRulesBotControlRuleSet: { InspectionLevel: 'TARGETED', EnableMachineLearning: true } }],
          RuleActionOverrides: ESCALATE_TO_LIVENESS_RULES.map((name) => ({ Name: name, ActionToUse: { Count: {} } })),
        }),
      },
    })]),
  });
});

test('Bot Control is pinned to a static version, never the default', () => {
  const [acl] = Object.values(template.findResources('AWS::WAFv2::WebACL')) as any[];
  const botControl = acl.Properties.Rules.find((r: any) => r.Name === 'AWS-BotControl');
  assert.equal(botControl.Statement.ManagedRuleGroupStatement.Version, 'Version_7.0');
});

test('every escalated rule exists in the pinned Bot Control version', () => {
  // AWS WAF accepts overrides for rule names that don't exist in the version,
  // so a typo or a rule added in a later version would fail silently.
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'bot-control-version-7.0-rules.json'), 'utf8'));
  const missing = ESCALATE_TO_LIVENESS_RULES.filter((rule) => !fixture.rules.includes(rule));
  assert.deepEqual(missing, []);
});

test('the flag rule inserts the header Lambda@Edge reads', () => {
  template.hasResourceProperties('AWS::WAFv2::WebACL', {
    Rules: Match.arrayWith([Match.objectLike({
      Name: 'FlagSuspectedBrowserAgents',
      Action: { Count: { CustomRequestHandling: { InsertHeaders: [{ Name: 'bot-suspect', Value: 'true' }] } } },
    })]),
  });
});

test('WAF logs redact the Cookie header', () => {
  template.hasResourceProperties('AWS::WAFv2::LoggingConfiguration', {
    RedactedFields: [{ SingleHeader: { Name: 'cookie' } }],
  });
});

test('the demo trigger can be disabled', () => {
  const { template: t } = synth({ enableDemoTrigger: false });
  const [acl] = Object.values(t.findResources('AWS::WAFv2::WebACL')) as any[];
  assert.ok(!acl.Properties.Rules.some((r: any) => r.Name === 'DemoTrigger'));
});

test('the gate runs on viewer request for the default behavior; the API on origin request', () => {
  const [dist] = Object.values(template.findResources('AWS::CloudFront::Distribution')) as any[];
  const config = dist.Properties.DistributionConfig;
  assert.deepEqual(config.DefaultCacheBehavior.LambdaFunctionAssociations.map((a: any) => a.EventType), ['viewer-request']);

  const byPath = Object.fromEntries(config.CacheBehaviors.map((b: any) => [b.PathPattern, b]));
  assert.deepEqual(byPath['/liveness/*'].LambdaFunctionAssociations.map((a: any) => a.EventType), ['origin-request']);
  assert.equal(byPath['/liveness/*'].ViewerProtocolPolicy, 'https-only');
  assert.equal(byPath['/challenge/*'].LambdaFunctionAssociations, undefined);
  assert.ok(config.WebACLId);
});

test('guest credentials can only stream video to Face Liveness', () => {
  const policies = template.findResources('AWS::IAM::Policy', {
    Properties: { Roles: [{ Ref: Match.stringLikeRegexp('LivenessIdentityPoolUnauthenticatedRole') }] },
  });
  const statements = Object.values(policies).flatMap((p: any) => p.Properties.PolicyDocument.Statement);
  assert.deepEqual(statements, [{ Action: 'rekognition:StartFaceLivenessSession', Effect: 'Allow', Resource: '*' }]);
  const [pool] = Object.values(template.findResources('AWS::Cognito::IdentityPool')) as any[];
  assert.equal(pool.Properties.AllowUnauthenticatedIdentities, true);
  assert.notEqual(pool.Properties.AllowClassicFlow, true);
});

test('face search and enrollment are scoped to the collection', () => {
  const statements = Object.values(template.findResources('AWS::IAM::Policy'))
    .flatMap((p: any) => p.Properties.PolicyDocument.Statement)
    .filter((s: any) => [].concat(s.Action).includes('rekognition:SearchFacesByImage' as never));
  assert.equal(statements.length, 1);
  assert.deepEqual([...statements[0].Action].sort(), ['rekognition:IndexFaces', 'rekognition:SearchFacesByImage']);
  assert.match(JSON.stringify(statements[0].Resource), /:collection\/test-bot-defense-verified-humans/);
});

test('every bucket blocks public access and enforces TLS', () => {
  const buckets = Object.values(template.findResources('AWS::S3::Bucket')) as any[];
  assert.ok(buckets.length >= 2);
  for (const bucket of buckets) {
    assert.deepEqual(bucket.Properties.PublicAccessBlockConfiguration, {
      BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true,
    });
  }
  const policies = Object.values(template.findResources('AWS::S3::BucketPolicy')) as any[];
  for (const policy of policies) {
    for (const statement of policy.Properties.PolicyDocument.Statement) {
      if (statement.Effect === 'Allow') assert.notEqual(statement.Principal, '*');
    }
  }
});

test('face vectors are cleaned up from the registry stream and a daily sweep', () => {
  template.hasResourceProperties('AWS::Lambda::EventSourceMapping', {
    FilterCriteria: { Filters: [{ Pattern: Match.stringLikeRegexp('REMOVE.*FACE#') }] },
    DestinationConfig: { OnFailure: { Destination: Match.anyValue() } },
  });
  template.hasResourceProperties('AWS::Events::Rule', { ScheduleExpression: 'rate(1 day)' });
  template.hasResource('AWS::Rekognition::Collection', { DeletionPolicy: 'Delete' });
});

test('the challenge page CSP allows only the endpoints Face Liveness needs', () => {
  template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
    ResponseHeadersPolicyConfig: Match.objectLike({
      SecurityHeadersConfig: Match.objectLike({
        ContentSecurityPolicy: {
          ContentSecurityPolicy: Match.stringLikeRegexp("wss://streaming-rekognition\\.us-east-1\\.amazonaws\\.com.*frame-ancestors 'none'"),
          Override: true,
        },
      }),
    }),
  });
});

test('cdk-nag AwsSolutions reports no unacknowledged violations', () => {
  const report = new AwsSolutionsChecks(app).validateScope(stack);
  assert.deepEqual(report.violations.map((v) => `${v.ruleName}: ${v.violatingResources.map((r) => (r as any).constructPath).join(', ')}`), []);
  assert.equal(report.success, true);
});

test('the stack refuses Regions other than us-east-1', () => {
  const app = new cdk.App();
  assert.throws(() => new AgenticBotDefenseStack(app, 'Wrong', {
    env: { account: '111111111111', region: 'eu-west-1' },
    settings: SETTINGS,
    challengePageAssetPath: os.tmpdir(),
    siteAssetPath: os.tmpdir(),
  }), /us-east-1/);
});
