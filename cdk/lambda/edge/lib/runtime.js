'use strict';

/**
 * Default dependencies for the deployed functions.
 *
 * Lambda@Edge does not support environment variables, so CDK writes a
 * config.json next to this code at synth time. It holds resource names and
 * tuning values only; the signing key stays in AWS Secrets Manager.
 *
 * All AWS calls go to the stack's home Region (us-east-1), wherever the
 * function happens to run. AWS SDK for JavaScript v3 is provided by the Lambda
 * Node.js runtime and is not bundled, which keeps the package well under the
 * Lambda@Edge size limit.
 */
let cached;

function loadRuntime() {
  if (cached) return cached;
  // eslint-disable-next-line global-require
  const config = require('../config.json');
  const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
  const { createKeyProvider } = require('./signing-key');

  const getSigningKey = createKeyProvider({
    client: new SecretsManagerClient({ region: config.region }),
    secretId: config.secretId,
  });

  cached = { config, getSigningKey };
  return cached;
}

module.exports = { loadRuntime };
