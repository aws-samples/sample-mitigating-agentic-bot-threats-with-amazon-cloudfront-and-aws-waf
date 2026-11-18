'use strict';

/**
 * Lambda@Edge - viewer request - default cache behavior.
 *
 * Detection and response are decoupled:
 *   - AWS WAF Bot Control decides WHEN to challenge. A custom rule matches the
 *     Bot Control labels that suggest an automated browser and inserts the
 *     request header "x-amzn-waf-bot-suspect: true". CloudFront runs this
 *     function after AWS WAF has evaluated the request.
 *   - This function decides HOW to respond. A flagged request passes only with
 *     a valid human-session cookie that is bound to this request's AWS WAF
 *     token. Anything else is sent to the Face Liveness challenge page.
 *
 * Binding the cookie to the AWS WAF token means a shared cookie only works
 * together with a shared AWS WAF token, which Bot Control's token-reuse rules
 * track across IPs, countries, and networks.
 *
 * Requests that are not flagged pass straight through with no network calls.
 */

const crypto = require('crypto');
const C = require('./lib/constants');
const token = require('./lib/token');
const { parseCookies, serializeCookie } = require('./lib/cookies');
const { json, redirect, safeRelativePath } = require('./lib/responses');
const { isFlagged, wafTokenId } = require('./lib/waf');

/**
 * Dot segments ("/./", "/../"), empty segments ("//"), and encoded dots,
 * slashes, or backslashes. CloudFront normalizes the path to pick a cache
 * behavior but forwards the raw path, so a path like "/challenge/../x" can be
 * matched differently by AWS WAF, CloudFront, and the origin. The web ACL
 * normalizes before matching; this is the backstop for the default behavior.
 */
const NON_NORMALIZED_PATH = /\/\.\.?(\/|$)|\/\/|\\|%2e|%2f|%5c/i;

const header = (request, name) => request.headers[name]?.[0]?.value || '';

/**
 * A top-level page load: the only request that may set the challenge cookie,
 * because that cookie carries the return path. Sec-Fetch-Dest is sent by
 * current browsers; Accept is the fallback for clients that omit it.
 */
function isTopLevelNavigation(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const dest = header(request, 'sec-fetch-dest');
  if (dest) return dest === 'document';
  return header(request, 'accept').toLowerCase().includes('text/html');
}

function createGateHandler({ config, getSigningKey, now = Date.now, newId = crypto.randomUUID }) {
  return async function handler(event) {
    const request = event.Records[0].cf.request;

    if (NON_NORMALIZED_PATH.test(request.uri)) {
      console.log(JSON.stringify({ event: 'invalid_path_rejected', method: request.method }));
      return json(400, { error: 'invalid_path' });
    }

    if (!isFlagged(request.headers)) return request;

    const key = await getSigningKey();
    if (!key) {
      // Fail closed: a flagged request is never let through unverified.
      return json(503, { error: 'verification_unavailable' });
    }

    const tid = wafTokenId(request.headers);
    const cookies = parseCookies(request.headers);
    const session = token.verify(cookies[C.HUMAN_COOKIE], key, C.TOKEN_TYPES.HUMAN, now());
    if (session && tid && session.tid === tid) return request;

    // Never log token IDs or cookie values.
    let reason = 'no_session';
    if (session) reason = tid ? 'waf_token_mismatch' : 'waf_token_missing';

    // Subresources (favicon, images, scripts), fetch/XHR calls, and form posts
    // get a 403 and leave the challenge cookie alone. The cookie is scoped to
    // /liveness, so the gate can't see one it already set; minting a new one
    // here would replace the return path with, for example, /favicon.ico.
    if (!isTopLevelNavigation(request)) {
      console.log(JSON.stringify({ event: 'verification_required', method: request.method, reason }));
      return json(403, { error: 'human_verification_required', challenge: C.CHALLENGE_PAGE });
    }

    // Bind the challenge to this browser with a short-lived signed cookie. Only
    // a browser holding it, with the same AWS WAF token, can create a Face
    // Liveness session. The return path travels inside the signature instead
    // of a query parameter.
    const returnTo = safeRelativePath(request.uri + (request.querystring ? `?${request.querystring}` : ''));
    const challenge = token.sign({
      v: 2,
      typ: C.TOKEN_TYPES.CHALLENGE,
      jti: newId(),
      tid,
      rt: returnTo,
      exp: now() + config.challengeTtlSeconds * 1000,
    }, key);
    const setCookie = serializeCookie(C.CHALLENGE_COOKIE, challenge, {
      path: C.LIVENESS_API_PATH,
      maxAgeSeconds: config.challengeTtlSeconds,
      sameSite: 'Strict',
    });

    console.log(JSON.stringify({ event: 'challenge_issued', method: request.method, reason }));
    return redirect(C.CHALLENGE_PAGE, [setCookie]);
  };
}

let deployedHandler;
exports.handler = async (event) => {
  if (!deployedHandler) {
    // eslint-disable-next-line global-require
    const { config, getSigningKey } = require('./lib/runtime').loadRuntime();
    deployedHandler = createGateHandler({ config, getSigningKey });
  }
  return deployedHandler(event);
};

exports.createGateHandler = createGateHandler;
