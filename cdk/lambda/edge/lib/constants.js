'use strict';

// AWS WAF prefixes every header it inserts with "x-amzn-waf-". The web ACL rule
// inserts "bot-suspect: true", so Lambda@Edge reads "x-amzn-waf-bot-suspect".
const SUSPECT_HEADER = 'x-amzn-waf-bot-suspect';

// The AWS WAF token's client session ID (label awswaf:managed:token:id:<id>),
// inserted by the ForwardWafTokenId rule. Every signed cookie carries the ID of
// the request that minted it, and every check requires the current request's
// ID to match, so a cookie only works together with its AWS WAF token.
const TOKEN_ID_HEADER = 'x-amzn-waf-token-id';

// Cookie names. "__Host-" requires Secure, Path=/ and no Domain attribute, which
// stops a sibling subdomain from planting a session cookie. "__Secure-" is used for
// the short-lived cookies that are scoped to the /liveness API path.
const HUMAN_COOKIE = '__Host-hv_session';
const CHALLENGE_COOKIE = '__Secure-hv_challenge';
const LIVENESS_COOKIE = '__Secure-hv_liveness';

const LIVENESS_API_PATH = '/liveness';
const CHALLENGE_PAGE = '/challenge/index.html';

// Token types. Every signed token carries its type so a token minted for one
// purpose can never be replayed as another (for example, a liveness token as a
// human-session token).
const TOKEN_TYPES = Object.freeze({
  CHALLENGE: 'challenge',
  LIVENESS: 'liveness',
  HUMAN: 'human',
});

module.exports = {
  SUSPECT_HEADER,
  TOKEN_ID_HEADER,
  HUMAN_COOKIE,
  CHALLENGE_COOKIE,
  LIVENESS_COOKIE,
  LIVENESS_API_PATH,
  CHALLENGE_PAGE,
  TOKEN_TYPES,
};
