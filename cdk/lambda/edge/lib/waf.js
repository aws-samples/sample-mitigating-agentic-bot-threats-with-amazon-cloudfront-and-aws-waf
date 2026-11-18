'use strict';

const C = require('./constants');

const MAX_TOKEN_ID_LENGTH = 512;

/** True when AWS WAF flagged the request for human verification. */
function isFlagged(headers) {
  return (headers[C.SUSPECT_HEADER] || []).some((h) => String(h.value).toLowerCase() === 'true');
}

/**
 * The AWS WAF token's client session ID for this request, or null when AWS WAF
 * didn't forward one (no token, or the path is outside Bot Control's scope).
 * The web ACL blocks client-sent "x-amzn-waf-" headers, so only AWS WAF can set it.
 */
function wafTokenId(headers) {
  const values = (headers[C.TOKEN_ID_HEADER] || []).map((h) => String(h.value).trim());
  if (values.length !== 1) return null;
  const [id] = values;
  if (id.length === 0 || id.length > MAX_TOKEN_ID_LENGTH || id.includes(',')) return null;
  return id;
}

module.exports = { isFlagged, wafTokenId };
