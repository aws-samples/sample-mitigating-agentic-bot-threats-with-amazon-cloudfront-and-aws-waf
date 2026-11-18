'use strict';

/**
 * Lambda@Edge - origin request - "/liveness/*" cache behavior.
 *
 * Generates every response itself; requests never reach the origin.
 *
 *   POST /liveness/session  Create an Amazon Rekognition Face Liveness session
 *                           for a browser that holds a challenge cookie.
 *   POST /liveness/verify   Read the session results, require a live person,
 *                           run the sybil check, and issue the human-session
 *                           cookie.
 *
 * The browser never chooses the session ID it is verified against: the ID
 * travels in a signed, HttpOnly cookie set by /liveness/session. The browser
 * also never sees the confidence score, only pass or fail.
 *
 * Every cookie carries the AWS WAF token ID of the request that minted it,
 * and each step requires the current request's token ID to match. The face
 * check must start and finish with the same AWS WAF token, and the resulting
 * human-session cookie only works together with that token.
 */

const {
  CreateFaceLivenessSessionCommand,
  GetFaceLivenessSessionResultsCommand,
} = require('@aws-sdk/client-rekognition');
const C = require('./lib/constants');
const token = require('./lib/token');
const { parseCookies, serializeCookie, clearCookie } = require('./lib/cookies');
const { json, safeRelativePath } = require('./lib/responses');
const { wafTokenId } = require('./lib/waf');

const API_COOKIE_OPTIONS = { path: C.LIVENESS_API_PATH, sameSite: 'Strict' };

/** Log a token-binding failure. Never logs token IDs or cookie values. */
function logTokenMismatch(step, tid) {
  console.log(JSON.stringify({ event: 'waf_token_mismatch', step, reason: tid ? 'different_token' : 'no_token' }));
}

function header(headers, name) {
  return headers[name]?.[0]?.value || '';
}

/**
 * Cross-site request defenses (in addition to SameSite=Strict cookies, which a
 * cross-site request never carries):
 *   - require a JSON content type, which forces a CORS preflight that this API
 *     never approves;
 *   - when the browser sends Sec-Fetch-Site, require "same-origin".
 */
function isSameOriginJsonRequest(headers) {
  if (!header(headers, 'content-type').toLowerCase().startsWith('application/json')) return false;
  const site = header(headers, 'sec-fetch-site');
  return site === '' || site === 'same-origin';
}

function createLivenessHandler({ config, getSigningKey, rekognition, sybilGuard, now = Date.now }) {
  async function createSession(cookies, key, tid) {
    const challenge = token.verify(cookies[C.CHALLENGE_COOKIE], key, C.TOKEN_TYPES.CHALLENGE, now());
    if (!challenge) return json(403, { error: 'challenge_required' });
    if (!tid || challenge.tid !== tid) {
      logTokenMismatch('session', tid);
      return json(403, { error: 'waf_token_mismatch' });
    }

    const created = await rekognition.send(new CreateFaceLivenessSessionCommand({
      Settings: {
        // No audit images: nothing beyond the reference image is retrieved, and
        // the reference image is only held in memory for the face search.
        AuditImagesLimit: 0,
        // Randomized face movement plus a colored light sequence.
        ChallengePreferences: [{ Type: 'FaceMovementAndLightChallenge' }],
      },
    }));

    const liveness = token.sign({
      v: 2,
      typ: C.TOKEN_TYPES.LIVENESS,
      sid: created.SessionId,
      tid,
      rt: challenge.rt,
      exp: now() + config.livenessTtlSeconds * 1000,
    }, key);

    console.log(JSON.stringify({ event: 'liveness_session_created' }));
    return json(200, { sessionId: created.SessionId, region: config.region }, [
      serializeCookie(C.LIVENESS_COOKIE, liveness, { ...API_COOKIE_OPTIONS, maxAgeSeconds: config.livenessTtlSeconds }),
    ]);
  }

  async function verifySession(cookies, key, tid) {
    const liveness = token.verify(cookies[C.LIVENESS_COOKIE], key, C.TOKEN_TYPES.LIVENESS, now());
    if (!liveness) return json(403, { verified: false, error: 'liveness_session_required' });

    const clearLiveness = clearCookie(C.LIVENESS_COOKIE, API_COOKIE_OPTIONS);

    // Checked before the session is consumed, so a copied liveness cookie
    // presented with another AWS WAF token can't burn the owner's session.
    if (!tid || liveness.tid !== tid) {
      logTokenMismatch('verify', tid);
      return json(403, { verified: false, error: 'waf_token_mismatch' }, [clearLiveness]);
    }

    // Each Face Liveness session can mint at most one human session.
    if (!(await sybilGuard.consumeSession(liveness.sid))) {
      return json(409, { verified: false, error: 'session_already_used' }, [clearLiveness]);
    }

    const result = await rekognition.send(new GetFaceLivenessSessionResultsCommand({ SessionId: liveness.sid }));
    const confidence = typeof result.Confidence === 'number' ? result.Confidence : -1;
    const isLive = result.Status === 'SUCCEEDED' && confidence >= config.livenessConfidenceThreshold;

    // Log the score server-side so the threshold can be tuned; never return it.
    console.log(JSON.stringify({
      event: 'liveness_result',
      status: result.Status,
      confidence: Math.round(confidence * 100) / 100,
      passed: isLive,
      feedback: (result.Feedback || []).map((f) => f.Code),
    }));

    if (!isLive) return json(403, { verified: false, error: 'liveness_check_failed' }, [clearLiveness]);

    const referenceImage = result.ReferenceImage?.Bytes;
    if (!referenceImage || referenceImage.length === 0) {
      // Rekognition recommends a retry when no reference image is returned.
      return json(403, { verified: false, error: 'liveness_check_failed' }, [clearLiveness]);
    }

    const decision = await sybilGuard.evaluate(referenceImage);
    console.log(JSON.stringify({ event: 'sybil_decision', allowed: decision.allowed, reason: decision.reason, enrolled: decision.enrolled }));
    if (!decision.allowed) {
      if (decision.reason === 'verification_limit_reached') {
        return json(429, { verified: false, error: 'too_many_verifications' }, [clearLiveness]);
      }
      return json(403, { verified: false, error: 'liveness_check_failed' }, [clearLiveness]);
    }

    const human = token.sign({
      v: 2,
      typ: C.TOKEN_TYPES.HUMAN,
      sid: liveness.sid,
      tid,
      exp: now() + config.humanSessionMinutes * 60 * 1000,
    }, key);

    return json(200, { verified: true, redirectUri: safeRelativePath(liveness.rt) }, [
      serializeCookie(C.HUMAN_COOKIE, human, { path: '/', maxAgeSeconds: config.humanSessionMinutes * 60, sameSite: 'Lax' }),
      clearLiveness,
      clearCookie(C.CHALLENGE_COOKIE, API_COOKIE_OPTIONS),
    ]);
  }

  return async function handler(event) {
    const request = event.Records[0].cf.request;

    if (request.method !== 'POST') {
      return json(405, { error: 'method_not_allowed' }, [], { allow: [{ key: 'Allow', value: 'POST' }] });
    }
    if (!isSameOriginJsonRequest(request.headers)) return json(400, { error: 'invalid_request' });

    const key = await getSigningKey();
    if (!key) return json(503, { error: 'verification_unavailable' });

    const cookies = parseCookies(request.headers);
    const tid = wafTokenId(request.headers);
    try {
      switch (request.uri) {
        case `${C.LIVENESS_API_PATH}/session`:
          return await createSession(cookies, key, tid);
        case `${C.LIVENESS_API_PATH}/verify`:
          return await verifySession(cookies, key, tid);
        default:
          return json(404, { error: 'not_found' });
      }
    } catch (error) {
      // Error class only: never echo AWS error messages to the client or log image data.
      console.error(JSON.stringify({ event: 'liveness_api_error', route: request.uri, error: error.name }));
      if (error.name === 'SessionNotFoundException') {
        return json(403, { verified: false, error: 'liveness_session_expired' });
      }
      return json(502, { error: 'verification_unavailable' });
    }
  };
}

let deployedHandler;
exports.handler = async (event) => {
  if (!deployedHandler) {
    /* eslint-disable global-require */
    const { RekognitionClient } = require('@aws-sdk/client-rekognition');
    const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
    const { createSybilGuard } = require('./lib/sybil-guard');
    const { config, getSigningKey } = require('./lib/runtime').loadRuntime();
    /* eslint-enable global-require */

    const rekognition = new RekognitionClient({ region: config.region });
    const ddb = new DynamoDBClient({ region: config.region });
    deployedHandler = createLivenessHandler({
      config,
      getSigningKey,
      rekognition,
      sybilGuard: createSybilGuard({ rekognition, ddb, config }),
    });
  }
  return deployedHandler(event);
};

exports.createLivenessHandler = createLivenessHandler;
