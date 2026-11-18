#!/usr/bin/env node
// Post-deploy smoke test. Usage: node scripts/smoke-test.mjs https://dxxxx.cloudfront.net
//
// Exercises the deployed edge without a camera or a browser: AWS WAF is
// attached, client-forged AWS WAF headers are blocked, the demo trigger
// escalates page loads to the challenge, flagged subresources get a 403
// without a new challenge cookie, dot-segment paths are normalized by AWS WAF
// and rejected by the gate, the challenge page and its headers are served,
// and the liveness API refuses requests that lack its cookies or an AWS WAF
// token. It creates no Face Liveness session.
//
// This client never holds an AWS WAF token, so it can't run the full flow:
// test that from a browser (README, "Test it"). Bot Control also evaluates
// the liveness API, so a token-less client may get an AWS WAF challenge
// instead of the API's own response. Both outcomes pass; neither creates a
// session. Repeated runs within 5 minutes can trip TGT_VolumetricIpTokenAbsent.

import https from 'node:https';

const base = (process.argv[2] || '').replace(/\/$/, '');
if (!/^https:\/\/[a-z0-9.-]+$/.test(base)) {
  console.error('Usage: node scripts/smoke-test.mjs https://<distribution-domain>');
  process.exit(2);
}

const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const CURL_UA = 'curl/8.7.1';
const results = [];

const parseJson = (text) => { try { return JSON.parse(text); } catch { return undefined; } };

async function call(path, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    redirect: 'manual',
    headers: { 'user-agent': BROWSER_UA, accept: '*/*', ...headers },
    body,
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    cookies: response.headers.getSetCookie(),
    wafAction: response.headers.get('x-amzn-waf-action'),
    text,
    json: parseJson(text),
  };
}

/** GET with the path sent byte for byte. fetch() would resolve "..". */
function rawGet(path, headers = {}) {
  const { hostname } = new URL(base);
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path, method: 'GET', headers: { 'user-agent': BROWSER_UA, accept: '*/*', ...headers } },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolve({
          status: res.statusCode,
          wafAction: res.headers['x-amzn-waf-action'],
          text,
          json: parseJson(text),
        }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

const cookie = (res, name) => {
  const c = res.cookies.find((v) => v.startsWith(`${name}=`));
  return c ? c.split(';')[0] : undefined;
};

/** The API answered as expected, or AWS WAF intercepted it before the origin. */
function apiOrWaf(res, expectedStatus, expectedError) {
  if (res.wafAction) return { ok: true, detail: `AWS WAF ${res.wafAction} (HTTP ${res.status})` };
  const ok = res.status === expectedStatus && (!expectedError || res.json?.error === expectedError);
  return { ok, detail: `HTTP ${res.status}${res.json?.error ? ` ${res.json.error}` : ''}` };
}

// 1. Public demo page is reachable. A first HTML request without an AWS WAF
//    token gets the silent Challenge (HTTP 202), which proves the web ACL is attached.
const home = await call('/', { headers: { accept: 'text/html' } });
check('demo site reachable through AWS WAF', [200, 202].includes(home.status), `HTTP ${home.status}`);

// 2. A client can't forge the token-ID header the cookies are bound to.
const spoof = await call('/', { headers: { 'x-amzn-waf-token-id': 'forged' } });
check('client-sent x-amzn-waf-token-id is blocked', spoof.status === 403, `HTTP ${spoof.status}`);

// 3. A flagged page load (demo trigger) is escalated to the challenge page.
//    Accept stays */* so the silent-Challenge rule (HTML GETs without a token)
//    doesn't answer first; Sec-Fetch-Dest marks it as a page load.
const flagged = await call('/checkout.html?simulate-agent=1', { headers: { 'sec-fetch-dest': 'document' } });
const challengeCookie = cookie(flagged, '__Secure-hv_challenge');
check('flagged page load redirects to the challenge',
  flagged.status === 302 && flagged.headers.get('location') === '/challenge/index.html' && Boolean(challengeCookie),
  flagged.wafAction
    ? `AWS WAF ${flagged.wafAction}; rerun after 5 minutes`
    : `HTTP ${flagged.status} -> ${flagged.headers.get('location')}`);

// 4. A flagged subresource gets a 403 and no challenge cookie, so it can't
//    replace the return path of the page load above.
const favicon = await call('/favicon.ico?simulate-agent=1', { headers: { 'sec-fetch-dest': 'image' } });
const faviconOutcome = apiOrWaf(favicon, 403, 'human_verification_required');
check('flagged subresource gets 403 without a challenge cookie',
  faviconOutcome.ok && !cookie(favicon, '__Secure-hv_challenge'), faviconOutcome.detail);

// 5. Dot segments. AWS WAF matches the normalized path, so "/challenge/.."
//    doesn't skip Bot Control: a curl user agent is blocked by AWS WAF, not
//    by the gate or the origin. A browser user agent reaches the gate, which
//    rejects the non-normalized path.
const dotPath = '/challenge/../index.html';
const dotCurl = await rawGet(dotPath, { 'user-agent': CURL_UA });
const blockedByWaf = dotCurl.status === 403 && dotCurl.json?.error !== 'invalid_path' && !dotCurl.text.includes('AccessDenied');
check('dot-segment path is still in Bot Control scope (curl blocked by AWS WAF)', blockedByWaf,
  `HTTP ${dotCurl.status}${dotCurl.json?.error ? ` ${dotCurl.json.error}` : ''}${dotCurl.text.includes('AccessDenied') ? ' S3 AccessDenied' : ''}`);
const dotBrowser = await rawGet(dotPath);
const dotOutcome = apiOrWaf(dotBrowser, 400, 'invalid_path');
check('gate rejects a dot-segment path', dotOutcome.ok, dotOutcome.detail);

// 6. Challenge page and runtime config are served with the expected headers.
const page = await call('/challenge/index.html');
const csp = page.headers.get('content-security-policy') || '';
check('challenge page served', page.status === 200 && page.text.includes('id="root"'), `HTTP ${page.status}`);
check('challenge page CSP allows Rekognition streaming', csp.includes('wss://streaming-rekognition.us-east-1.amazonaws.com'));
check('challenge page allows the camera', (page.headers.get('permissions-policy') || '').includes('camera=(self)'));
const config = await call('/challenge/config.json');
check('runtime config has an identity pool', /^us-east-1:[0-9a-f-]{36}$/.test(config.json?.identityPoolId || ''), config.json?.identityPoolId);

// 7. Liveness API refusals. None of these may create a Face Liveness session.
const json = { 'content-type': 'application/json' };
const wrongMethod = apiOrWaf(await call('/liveness/session'), 405, 'method_not_allowed');
check('liveness API rejects GET', wrongMethod.ok, wrongMethod.detail);

const noCookie = apiOrWaf(await call('/liveness/session', { method: 'POST', headers: json, body: '{}' }), 403, 'challenge_required');
check('liveness session requires the challenge cookie', noCookie.ok, noCookie.detail);

if (challengeCookie) {
  const noToken = await call('/liveness/session', { method: 'POST', headers: { ...json, cookie: challengeCookie }, body: '{}' });
  const outcome = apiOrWaf(noToken, 403, 'waf_token_mismatch');
  check('liveness session requires an AWS WAF token', outcome.ok && !noToken.json?.sessionId, outcome.detail);
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed === 0 ? 0 : 1);
