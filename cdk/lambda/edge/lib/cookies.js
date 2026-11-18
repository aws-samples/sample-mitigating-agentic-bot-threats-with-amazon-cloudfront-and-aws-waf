'use strict';

const COOKIE_NAME_WITH_PREFIX = /^(__Host-|__Secure-)?[A-Za-z0-9_-]+$/;
const COOKIE_VALUE = /^[A-Za-z0-9._-]*$/;

/**
 * Parse every Cookie header CloudFront passes to the function. When the same
 * cookie name appears more than once, the first occurrence wins.
 */
function parseCookies(headers) {
  const cookies = {};
  for (const header of (headers && headers.cookie) || []) {
    for (const part of String(header.value).split(';')) {
      const index = part.indexOf('=');
      if (index < 1) continue;
      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (!(name in cookies)) cookies[name] = value;
    }
  }
  return cookies;
}

/**
 * Serialize a Set-Cookie value. Cookies are always Secure and HttpOnly: no
 * client-side script ever needs to read them.
 */
function serializeCookie(name, value, { path = '/', maxAgeSeconds, sameSite = 'Lax' } = {}) {
  if (!COOKIE_NAME_WITH_PREFIX.test(name)) throw new Error('Invalid cookie name');
  if (!COOKIE_VALUE.test(value)) throw new Error('Invalid cookie value');
  if (name.startsWith('__Host-') && path !== '/') {
    throw new Error('__Host- cookies must use Path=/');
  }
  const attributes = [`${name}=${value}`, `Path=${path}`];
  if (typeof maxAgeSeconds === 'number') {
    attributes.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`);
  }
  attributes.push('Secure', 'HttpOnly', `SameSite=${sameSite}`);
  return attributes.join('; ');
}

function clearCookie(name, { path = '/', sameSite = 'Lax' } = {}) {
  return serializeCookie(name, '', { path, maxAgeSeconds: 0, sameSite });
}

module.exports = { parseCookies, serializeCookie, clearCookie };
