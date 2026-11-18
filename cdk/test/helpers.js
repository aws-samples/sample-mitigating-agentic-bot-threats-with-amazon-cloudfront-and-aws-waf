'use strict';

const KEY = 'test-signing-key-0123456789abcdef0123456789abcdef';

const CONFIG = Object.freeze({
  region: 'us-east-1',
  secretId: 'test/session-signing-key',
  tableName: 'test-human-verification',
  collectionId: 'test-verified-humans',
  livenessConfidenceThreshold: 90,
  faceMatchThreshold: 95,
  maxVerificationsPerFace: 5,
  verificationWindowHours: 24,
  faceRetentionDays: 30,
  humanSessionMinutes: 15,
  challengeTtlSeconds: 600,
  livenessTtlSeconds: 240,
});

/** Error shaped like an AWS SDK v3 service exception. */
class AwsError extends Error {
  constructor(name, message = name) {
    super(message);
    this.name = name;
  }
}

/** CloudFront Lambda@Edge request event. Header names are lowercased like CloudFront does. */
function cfEvent({ method = 'GET', uri = '/', querystring = '', headers = {} } = {}) {
  const cfHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    cfHeaders[name.toLowerCase()] = [].concat(value).map((v) => ({ key: name, value: v }));
  }
  return {
    Records: [{
      cf: {
        config: { distributionDomainName: 'd111111abcdef8.cloudfront.net', eventType: 'viewer-request' },
        request: { method, uri, querystring, headers: cfHeaders, clientIp: '192.0.2.10' },
      },
    }],
  };
}

/**
 * Fake AWS SDK client. `handlers` maps command class names to functions that
 * receive the command input; every call is recorded.
 */
function fakeClient(handlers = {}) {
  const calls = [];
  return {
    calls,
    callsTo: (name) => calls.filter((c) => c.name === name),
    async send(command) {
      const name = command.constructor.name;
      calls.push({ name, input: command.input });
      const handler = handlers[name];
      if (!handler) throw new Error(`Unexpected call: ${name}`);
      return handler(command.input);
    },
  };
}

function setCookies(response) {
  return (response.headers['set-cookie'] || []).map((h) => h.value);
}

/** Extract a cookie value from a Set-Cookie list. */
function cookieValue(response, name) {
  const header = setCookies(response).find((c) => c.startsWith(`${name}=`));
  return header ? header.split(';')[0].slice(name.length + 1) : undefined;
}

module.exports = { KEY, CONFIG, AwsError, cfEvent, fakeClient, setCookies, cookieValue };
