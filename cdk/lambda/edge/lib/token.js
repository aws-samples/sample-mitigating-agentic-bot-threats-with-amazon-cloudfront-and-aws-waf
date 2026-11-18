'use strict';

const crypto = require('crypto');

const MAX_TOKEN_LENGTH = 4096;

/**
 * Sign a payload as `base64url(json).base64url(hmac-sha256(base64url(json)))`.
 * The MAC is computed over the encoded body, so verification never depends on
 * JSON canonicalization.
 */
function sign(payload, key) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const mac = crypto.createHmac('sha256', key).update(body).digest('base64url');
  return `${body}.${mac}`;
}

/**
 * Verify a token and return its payload, or null when the token is missing,
 * malformed, tampered with, of the wrong type, or expired.
 */
function verify(token, key, expectedType, nowMs) {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, mac] = parts;

  const expected = crypto.createHmac('sha256', key).update(body).digest();
  const given = Buffer.from(mac, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (payload.typ !== expectedType) return null;
  if (typeof payload.exp !== 'number' || nowMs >= payload.exp) return null;
  return payload;
}

module.exports = { sign, verify };
