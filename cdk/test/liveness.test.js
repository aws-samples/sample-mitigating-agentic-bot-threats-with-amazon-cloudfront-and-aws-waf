'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createLivenessHandler } = require('../lambda/edge/liveness');
const token = require('../lambda/edge/lib/token');
const C = require('../lambda/edge/lib/constants');
const { KEY, CONFIG, AwsError, cfEvent, fakeClient, setCookies, cookieValue } = require('./helpers');

const NOW = 1_700_000_000_000;
const SESSION_ID = '0f959dbb-37cc-45d8-a08d-dc42cce85fa8';
const TID = 'waf-token-id-A';
const JSON_HEADERS = { 'content-type': 'application/json', 'sec-fetch-site': 'same-origin', 'x-amzn-waf-token-id': TID };
const IMAGE = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);

function setup({ results, sybilDecision = { allowed: true, enrolled: true }, consumed = true, key = KEY } = {}) {
  const rekognition = fakeClient({
    CreateFaceLivenessSessionCommand: () => ({ SessionId: SESSION_ID }),
    GetFaceLivenessSessionResultsCommand: () => {
      if (results instanceof Error) throw results;
      return results;
    },
  });
  const sybilCalls = { consume: [], evaluate: [] };
  const sybilGuard = {
    consumeSession: async (sid) => { sybilCalls.consume.push(sid); return consumed; },
    evaluate: async (bytes) => { sybilCalls.evaluate.push(bytes); return sybilDecision; },
  };
  const handler = createLivenessHandler({
    config: CONFIG,
    getSigningKey: async () => key,
    rekognition,
    sybilGuard,
    now: () => NOW,
  });
  return { handler, rekognition, sybilCalls };
}

const challengeCookie = (overrides = {}) => `${C.CHALLENGE_COOKIE}=${token.sign({ typ: 'challenge', rt: '/checkout.html?event=jazz', jti: 'j', tid: TID, exp: NOW + 60_000, ...overrides }, KEY)}`;
const livenessCookie = (overrides = {}) => `${C.LIVENESS_COOKIE}=${token.sign({ typ: 'liveness', sid: SESSION_ID, rt: '/checkout.html?event=jazz', tid: TID, exp: NOW + 60_000, ...overrides }, KEY)}`;
const withoutTokenId = () => {
  const { 'x-amzn-waf-token-id': _omit, ...rest } = JSON_HEADERS;
  return rest;
};

const post = (uri, cookie, headers = JSON_HEADERS) => cfEvent({ method: 'POST', uri, headers: cookie ? { ...headers, cookie } : headers });

test('only POST is accepted', async () => {
  const { handler } = setup();
  const response = await handler(cfEvent({ method: 'GET', uri: '/liveness/session' }));
  assert.equal(response.status, '405');
  assert.equal(response.headers.allow[0].value, 'POST');
});

test('requests without a JSON content type are rejected', async () => {
  const { handler } = setup();
  const response = await handler(post('/liveness/session', challengeCookie(), { 'content-type': 'text/plain' }));
  assert.equal(response.status, '400');
});

test('cross-site requests are rejected', async () => {
  const { handler } = setup();
  const response = await handler(post('/liveness/session', challengeCookie(), { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' }));
  assert.equal(response.status, '400');
});

test('a liveness session requires the challenge cookie issued by the gate', async () => {
  const { handler, rekognition } = setup();
  const response = await handler(post('/liveness/session'));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'challenge_required');
  assert.equal(rekognition.calls.length, 0);
});

test('creates a movement-and-light session with no audit images and binds it to a cookie', async () => {
  const { handler, rekognition } = setup();
  const response = await handler(post('/liveness/session', challengeCookie()));

  assert.equal(response.status, '200');
  assert.deepEqual(JSON.parse(response.body), { sessionId: SESSION_ID, region: 'us-east-1' });
  assert.deepEqual(rekognition.callsTo('CreateFaceLivenessSessionCommand')[0].input, {
    Settings: { AuditImagesLimit: 0, ChallengePreferences: [{ Type: 'FaceMovementAndLightChallenge' }] },
  });

  const liveness = token.verify(cookieValue(response, C.LIVENESS_COOKIE), KEY, 'liveness', NOW);
  assert.equal(liveness.sid, SESSION_ID);
  assert.equal(liveness.tid, TID);
  assert.equal(liveness.rt, '/checkout.html?event=jazz');
  assert.match(setCookies(response)[0], /Path=\/liveness; Max-Age=240; Secure; HttpOnly; SameSite=Strict$/);
});

test('a session is refused when the challenge cookie was issued to a different AWS WAF token', async () => {
  const { handler, rekognition } = setup();
  const response = await handler(post('/liveness/session', challengeCookie({ tid: 'waf-token-id-B' })));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'waf_token_mismatch');
  assert.equal(rekognition.calls.length, 0);
});

test('a session is refused when the request carries no AWS WAF token ID', async () => {
  const { handler, rekognition } = setup();
  const response = await handler(post('/liveness/session', challengeCookie(), withoutTokenId()));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'waf_token_mismatch');
  assert.equal(rekognition.calls.length, 0);
});

test('verify is refused with a different AWS WAF token, before the session is consumed', async () => {
  const { handler, rekognition, sybilCalls } = setup({
    results: { SessionId: SESSION_ID, Status: 'SUCCEEDED', Confidence: 99, ReferenceImage: { Bytes: IMAGE } },
  });
  const response = await handler(post('/liveness/verify', livenessCookie({ tid: 'waf-token-id-B' })));
  assert.equal(response.status, '403');
  assert.deepEqual(JSON.parse(response.body), { verified: false, error: 'waf_token_mismatch' });
  assert.equal(sybilCalls.consume.length, 0);
  assert.equal(rekognition.calls.length, 0);
  assert.equal(cookieValue(response, C.HUMAN_COOKIE), undefined);
});

test('verify is refused when the request carries no AWS WAF token ID', async () => {
  const { handler, sybilCalls } = setup();
  const response = await handler(post('/liveness/verify', livenessCookie(), withoutTokenId()));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'waf_token_mismatch');
  assert.equal(sybilCalls.consume.length, 0);
});

test('a live, unique person gets a human session and is sent back to the original page', async () => {
  const { handler, rekognition, sybilCalls } = setup({
    results: { SessionId: SESSION_ID, Status: 'SUCCEEDED', Confidence: 97.3, ReferenceImage: { Bytes: IMAGE } },
  });
  const response = await handler(post('/liveness/verify', livenessCookie()));

  assert.equal(response.status, '200');
  assert.deepEqual(JSON.parse(response.body), { verified: true, redirectUri: '/checkout.html?event=jazz' });
  assert.deepEqual(rekognition.callsTo('GetFaceLivenessSessionResultsCommand')[0].input, { SessionId: SESSION_ID });
  assert.deepEqual(sybilCalls.consume, [SESSION_ID]);
  assert.equal(sybilCalls.evaluate[0], IMAGE);

  const human = token.verify(cookieValue(response, C.HUMAN_COOKIE), KEY, 'human', NOW);
  assert.equal(human.exp, NOW + 15 * 60_000);
  assert.equal(human.tid, TID);
  const cookies = setCookies(response);
  assert.match(cookies[0], /^__Host-hv_session=.*; Path=\/; Max-Age=900; Secure; HttpOnly; SameSite=Lax$/);
  assert.ok(cookies.some((c) => c.startsWith(`${C.LIVENESS_COOKIE}=;`) && c.includes('Max-Age=0')));
  assert.ok(cookies.some((c) => c.startsWith(`${C.CHALLENGE_COOKIE}=;`) && c.includes('Max-Age=0')));
});

test('a low liveness score fails without revealing the score or reaching the face search', async () => {
  const { handler, sybilCalls } = setup({
    results: { SessionId: SESSION_ID, Status: 'SUCCEEDED', Confidence: 42.5, ReferenceImage: { Bytes: IMAGE } },
  });
  const response = await handler(post('/liveness/verify', livenessCookie()));

  assert.equal(response.status, '403');
  assert.deepEqual(JSON.parse(response.body), { verified: false, error: 'liveness_check_failed' });
  assert.doesNotMatch(response.body, /42/);
  assert.equal(sybilCalls.evaluate.length, 0);
  assert.equal(cookieValue(response, C.HUMAN_COOKIE), undefined);
});

test('a session that did not succeed fails even with a high score', async () => {
  const { handler } = setup({ results: { SessionId: SESSION_ID, Status: 'EXPIRED', Confidence: 99 } });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '403');
});

test('a missing reference image fails so the user retries', async () => {
  const { handler, sybilCalls } = setup({ results: { SessionId: SESSION_ID, Status: 'SUCCEEDED', Confidence: 99 } });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '403');
  assert.equal(sybilCalls.evaluate.length, 0);
});

test('a liveness session can mint only one human session', async () => {
  const { handler, rekognition } = setup({ consumed: false });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '409');
  assert.equal(rekognition.callsTo('GetFaceLivenessSessionResultsCommand').length, 0);
});

test('a face over its verification cap is refused with 429', async () => {
  const { handler } = setup({
    results: { SessionId: SESSION_ID, Status: 'SUCCEEDED', Confidence: 99, ReferenceImage: { Bytes: IMAGE } },
    sybilDecision: { allowed: false, reason: 'verification_limit_reached' },
  });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '429');
  assert.equal(JSON.parse(response.body).error, 'too_many_verifications');
  assert.equal(cookieValue(response, C.HUMAN_COOKIE), undefined);
});

test('verification needs the liveness cookie; a challenge token is not accepted in its place', async () => {
  const { handler } = setup();
  const forged = `${C.LIVENESS_COOKIE}=${token.sign({ typ: 'challenge', sid: SESSION_ID, exp: NOW + 60_000 }, KEY)}`;
  const response = await handler(post('/liveness/verify', forged));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'liveness_session_required');
});

test('an expired Rekognition session maps to a retryable error', async () => {
  const { handler } = setup({ results: new AwsError('SessionNotFoundException') });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '403');
  assert.equal(JSON.parse(response.body).error, 'liveness_session_expired');
});

test('AWS error details are not returned to the browser', async () => {
  const { handler } = setup({ results: new AwsError('InternalServerError', 'arn:aws:rekognition:internal detail') });
  const response = await handler(post('/liveness/verify', livenessCookie()));
  assert.equal(response.status, '502');
  assert.doesNotMatch(response.body, /arn:aws|detail/);
});

test('fails closed when the signing key is unavailable', async () => {
  const { handler } = setup({ key: null });
  const response = await handler(post('/liveness/session', challengeCookie()));
  assert.equal(response.status, '503');
});
