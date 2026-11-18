#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AgenticBotDefenseStack, HOME_REGION, HumanVerificationSettings } from '../lib/agentic-bot-defense-stack';

const app = new cdk.App();

function numberContext(key: string, min: number, max: number): number {
  const value = Number(app.node.tryGetContext(key));
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(`Context "${key}" must be a number between ${min} and ${max}.`);
  }
  return value;
}

const prefix = String(app.node.tryGetContext('prefix') ?? '');
if (!/^[a-z][a-z0-9-]{2,39}$/.test(prefix)) {
  throw new Error('Context "prefix" must be 3-40 characters: lowercase letters, digits, hyphens.');
}

// Never fall back to the rule group's default version (see BotControlWebAclProps).
const botControlVersion = String(app.node.tryGetContext('botControlVersion') ?? '');
if (!/^Version_\d+\.\d+$/.test(botControlVersion)) {
  throw new Error('Context "botControlVersion" must name a static version, for example "Version_7.0".');
}

const settings: HumanVerificationSettings = {
  prefix,
  botControlVersion,
  livenessConfidenceThreshold: numberContext('livenessConfidenceThreshold', 50, 100),
  faceMatchThreshold: numberContext('faceMatchThreshold', 80, 100),
  maxVerificationsPerFace: numberContext('maxVerificationsPerFace', 1, 1000),
  verificationWindowHours: numberContext('verificationWindowHours', 1, 24 * 30),
  faceRetentionDays: numberContext('faceRetentionDays', 1, 365),
  humanSessionMinutes: numberContext('humanSessionMinutes', 1, 24 * 60),
  enableDemoTrigger: String(app.node.tryGetContext('enableDemoTrigger')) === 'true',
};

const challengePageAssetPath = path.join(__dirname, '..', '..', 'web', 'challenge', 'dist');
if (!fs.existsSync(path.join(challengePageAssetPath, 'index.html'))) {
  throw new Error('Challenge page is not built. Run "npm run build:web" in the cdk directory first.');
}

const stack = new AgenticBotDefenseStack(app, 'AgenticBotDefenseStack', {
  description: 'AWS WAF Bot Control + Lambda@Edge + Amazon Rekognition Face Liveness step-up for agent-driven browser sessions',
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: HOME_REGION },
  settings,
  challengePageAssetPath,
  siteAssetPath: path.join(__dirname, '..', '..', 'web', 'site'),
});

// Optional tags for every resource, as "key=value,key2=value2". Useful when the
// account runs automated cleanup that skips tagged resources.
const stackTags = String(app.node.tryGetContext('stackTags') ?? '');
for (const pair of stackTags.split(',').map((s) => s.trim()).filter(Boolean)) {
  const index = pair.indexOf('=');
  const key = pair.slice(0, index).trim();
  const value = pair.slice(index + 1).trim();
  if (index < 1 || !value) throw new Error(`Context "stackTags" entries must be key=value; got "${pair}".`);
  cdk.Tags.of(stack).add(key, value);
}

cdk.Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
