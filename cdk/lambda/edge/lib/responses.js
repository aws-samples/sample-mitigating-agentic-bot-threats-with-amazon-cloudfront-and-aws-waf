'use strict';

const STATUS_TEXT = {
  200: 'OK',
  302: 'Found',
  400: 'Bad Request',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  409: 'Conflict',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
};

function baseHeaders(setCookies) {
  const headers = {
    'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    'x-content-type-options': [{ key: 'X-Content-Type-Options', value: 'nosniff' }],
  };
  if (setCookies && setCookies.length > 0) {
    headers['set-cookie'] = setCookies.map((value) => ({ key: 'Set-Cookie', value }));
  }
  return headers;
}

function json(status, body, setCookies = [], extraHeaders = {}) {
  return {
    status: String(status),
    statusDescription: STATUS_TEXT[status] || 'Error',
    headers: {
      ...baseHeaders(setCookies),
      'content-type': [{ key: 'Content-Type', value: 'application/json; charset=utf-8' }],
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

function redirect(location, setCookies = []) {
  return {
    status: '302',
    statusDescription: STATUS_TEXT[302],
    headers: {
      ...baseHeaders(setCookies),
      location: [{ key: 'Location', value: location }],
    },
  };
}

/**
 * Return a same-origin relative path, or "/" when the input could send the
 * browser to another origin ("//evil.example", "/\\evil.example", absolute
 * URLs, control characters).
 */
function safeRelativePath(candidate) {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 2048) return '/';
  if (!candidate.startsWith('/')) return '/';
  if (candidate.startsWith('//') || candidate.startsWith('/\\')) return '/';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(candidate)) return '/';
  return candidate;
}

module.exports = { json, redirect, safeRelativePath };
