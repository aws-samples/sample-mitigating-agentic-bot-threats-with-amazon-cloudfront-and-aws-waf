'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createGateHandler } = require('../lambda/edge/gate');
const token = require('../lambda/edge/lib/token');
const C = require('../lambda/edge/lib/constants');
const { KEY, CONFIG, cfEvent, setCookies, cookieValue } = require('./helpers');

const NOW = 1_700_000_000_000;
const TID = 'waf-token-id-A';
const FLAG = { 'x-amzn-waf-bot-suspect': 'true', 'x-amzn-waf-token-id': TID };
/** A flagged top-level page load, as a current browser sends it. */
const NAV = { 'sec-fetch-dest': 'document', accept: 'text/html,application/xhtml+xml,*/*;q=0.8' };
const FLAGGED_PAGE = { ...FLAG, ...NAV };

function gate({ key = KEY } = {}) {
  let keyCalls = 0;
  const handler = createGateHandler({
    config: CONFIG,
    getSigningKey: async () => { keyCalls += 1; return key; },
    now: () => NOW,
    newId: () => 'jti-1',
  });
  return { handler, keyCalls: () => keyCalls };
}

const humanCookie = (payload) => `${C.HUMAN_COOKIE}=${token.sign(payload, KEY)}`;
const validSession = (overrides = {}) => humanCookie({ typ: 'human', tid: TID, exp: NOW + 60_000, ...overrides });

function assertVerificationRequired(response) {
  assert.equal(response.status, '403');
  assert.deepEqual(JSON.parse(response.body), { error: 'human_verification_required', challenge: C.CHALLENGE_PAGE });
  assert.equal(response.headers['set-cookie'], undefined, 'must not replace the challenge cookie');
}

test('requests AWS WAF did not flag pass through without any network call', async () => {
  const { handler, keyCalls } = gate();
  const event = cfEvent({ uri: '/checkout.html', headers: NAV });
  assert.equal(await handler(event), event.Records[0].cf.request);
  assert.equal(keyCalls(), 0);
});

test('a flagged page load without a human session is redirected to the challenge page', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ uri: '/checkout.html', querystring: 'event=jazz', headers: FLAGGED_PAGE }));

  assert.equal(response.status, '302');
  assert.equal(response.headers.location[0].value, C.CHALLENGE_PAGE);
  assert.equal(response.headers['cache-control'][0].value, 'no-store');

  const [cookie] = setCookies(response);
  assert.match(cookie, /^__Secure-hv_challenge=/);
  assert.match(cookie, /Path=\/liveness; Max-Age=600; Secure; HttpOnly; SameSite=Strict$/);

  const challenge = token.verify(cookieValue(response, C.CHALLENGE_COOKIE), KEY, 'challenge', NOW);
  assert.equal(challenge.rt, '/checkout.html?event=jazz');
  assert.equal(challenge.exp, NOW + 600_000);
});

test('the challenge cookie is bound to the AWS WAF token of the flagged request', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: FLAGGED_PAGE }));
  const challenge = token.verify(cookieValue(response, C.CHALLENGE_COOKIE), KEY, 'challenge', NOW);
  assert.equal(challenge.tid, TID);
});

test('a flagged subresource request gets a 403 and leaves the challenge cookie alone', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({
    uri: '/favicon.ico',
    headers: { ...FLAG, 'sec-fetch-dest': 'image', accept: 'image/avif,image/webp,*/*' },
  }));
  assertVerificationRequired(response);
});

test('a flagged fetch() call gets a 403 and leaves the challenge cookie alone', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ uri: '/api/cart', headers: { ...FLAG, 'sec-fetch-dest': 'empty', accept: '*/*' } }));
  assertVerificationRequired(response);
});

test('a flagged framed page load is not treated as a navigation', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { ...FLAG, 'sec-fetch-dest': 'iframe', accept: 'text/html' } }));
  assertVerificationRequired(response);
});

test('without Sec-Fetch-Dest, an Accept header asking for HTML counts as a navigation', async () => {
  const { handler } = gate();
  const page = await handler(cfEvent({ headers: { ...FLAG, accept: 'text/html' } }));
  assert.equal(page.status, '302');
  const image = await handler(cfEvent({ uri: '/logo.png', headers: { ...FLAG, accept: 'image/png' } }));
  assertVerificationRequired(image);
});

test('a flagged non-GET request gets a 403 that points to the challenge, without a cookie', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ method: 'POST', uri: '/api/cart', headers: FLAGGED_PAGE }));
  assertVerificationRequired(response);
});

test('a flagged request with a human session bound to the same AWS WAF token passes through', async () => {
  const { handler } = gate();
  const event = cfEvent({ headers: { ...FLAGGED_PAGE, cookie: validSession() } });
  assert.equal(await handler(event), event.Records[0].cf.request);
});

test('a verified session also covers subresources', async () => {
  const { handler } = gate();
  const event = cfEvent({ uri: '/styles.css', headers: { ...FLAG, 'sec-fetch-dest': 'style', cookie: validSession() } });
  assert.equal(await handler(event), event.Records[0].cf.request);
});

test('a human session presented with a different AWS WAF token is challenged again', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { ...FLAGGED_PAGE, 'x-amzn-waf-token-id': 'waf-token-id-B', cookie: validSession() } }));
  assert.equal(response.status, '302');
});

test('a human session on a request without an AWS WAF token ID is challenged again', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { 'x-amzn-waf-bot-suspect': 'true', ...NAV, cookie: validSession() } }));
  assert.equal(response.status, '302');
});

test('a human session issued before token binding (no tid) is challenged again', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { ...FLAGGED_PAGE, cookie: humanCookie({ typ: 'human', exp: NOW + 60_000 }) } }));
  assert.equal(response.status, '302');
});

test('an expired human session is challenged again', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { ...FLAGGED_PAGE, cookie: validSession({ exp: NOW - 1 }) } }));
  assert.equal(response.status, '302');
});

test('a liveness token presented as a human session is rejected', async () => {
  const { handler } = gate();
  const response = await handler(cfEvent({ headers: { ...FLAGGED_PAGE, cookie: validSession({ typ: 'liveness' }) } }));
  assert.equal(response.status, '302');
});

test('fails closed when the signing key is unavailable', async () => {
  const { handler } = gate({ key: null });
  const response = await handler(cfEvent({ headers: FLAGGED_PAGE }));
  assert.equal(response.status, '503');
});

for (const uri of [
  '/challenge/../checkout.html',
  '/challenge/..',
  '/./checkout.html',
  '/a/.',
  '//evil.example/path',
  '/challenge/%2e%2e/checkout.html',
  '/challenge/%2E%2E/checkout.html',
  '/challenge%2f..%2fcheckout.html',
  '/challenge\\..\\checkout.html',
  '/challenge/%5c../checkout.html',
]) {
  test(`a non-normalized path is rejected before any other check: ${uri}`, async () => {
    const { handler, keyCalls } = gate();
    for (const headers of [NAV, FLAGGED_PAGE]) {
      const response = await handler(cfEvent({ uri, headers }));
      assert.equal(response.status, '400');
      assert.deepEqual(JSON.parse(response.body), { error: 'invalid_path' });
      assert.equal(response.headers['set-cookie'], undefined);
    }
    assert.equal(keyCalls(), 0);
  });
}

test('ordinary paths with dots in names are not rejected', async () => {
  const { handler } = gate();
  for (const uri of ['/checkout.html', '/assets/app.v2.js', '/.well-known/security.txt', '/a..b/c']) {
    const event = cfEvent({ uri, headers: NAV });
    assert.equal(await handler(event), event.Records[0].cf.request, uri);
  }
});
