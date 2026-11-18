'use strict';

const { GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

/**
 * Returns a function that resolves the HMAC signing key from AWS Secrets Manager.
 *
 * The key is cached per execution environment for `ttlMs`, so steady-state
 * requests make no network call. If a refresh fails, the last known key is used;
 * if no key has ever been fetched, the function resolves to null and callers must
 * fail closed.
 */
function createKeyProvider({ client, secretId, ttlMs = 5 * 60 * 1000, now = Date.now }) {
  let cachedKey = null;
  let fetchedAt = 0;

  return async function getSigningKey() {
    if (cachedKey && now() - fetchedAt < ttlMs) return cachedKey;
    try {
      const result = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
      if (!result.SecretString) throw new Error('Secret has no SecretString');
      cachedKey = result.SecretString;
      fetchedAt = now();
    } catch (error) {
      // Log the error class only. Never log secret material.
      console.error(JSON.stringify({ event: 'signing_key_fetch_failed', error: error.name }));
    }
    return cachedKey;
  };
}

module.exports = { createKeyProvider };
