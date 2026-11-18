'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const token = require('../lambda/edge/lib/token');
const { serializeCookie, parseCookies } = require('../lambda/edge/lib/cookies');
const { safeRelativePath } = require('../lambda/edge/lib/responses');
const { KEY } = require('./helpers');

const NOW = 1_700_000_000_000;

test('a signed token round-trips', () => {
  const t = token.sign({ typ: 'human', exp: NOW + 1000, sid: 'abc' }, KEY);
  assert.deepEqual(token.verify(t, KEY, 'human', NOW), { typ: 'human', exp: NOW + 1000, sid: 'abc' });
});

test('a token signed with another key is rejected', () => {
  const t = token.sign({ typ: 'human', exp: NOW + 1000 }, 'another-key');
  assert.equal(token.verify(t, KEY, 'human', NOW), null);
});

test('a tampered payload is rejected', () => {
  const t = token.sign({ typ: 'human', exp: NOW + 1000 }, KEY);
  const [, mac] = t.split('.');
  const forged = Buffer.from(JSON.stringify({ typ: 'human', exp: NOW + 10_000_000 })).toString('base64url');
  assert.equal(token.verify(`${forged}.${mac}`, KEY, 'human', NOW), null);
});

test('an expired token is rejected', () => {
  const t = token.sign({ typ: 'human', exp: NOW }, KEY);
  assert.equal(token.verify(t, KEY, 'human', NOW), null);
});

test('a token of another type is rejected', () => {
  const t = token.sign({ typ: 'liveness', exp: NOW + 1000 }, KEY);
  assert.equal(token.verify(t, KEY, 'human', NOW), null);
});

test('malformed and oversized tokens are rejected', () => {
  for (const bad of [undefined, '', 'abc', 'a.b.c', 'x'.repeat(5000), '!!!.???']) {
    assert.equal(token.verify(bad, KEY, 'human', NOW), null);
  }
});

test('cookies are always Secure and HttpOnly', () => {
  const c = serializeCookie('__Secure-x', 'v', { path: '/liveness', maxAgeSeconds: 60, sameSite: 'Strict' });
  assert.equal(c, '__Secure-x=v; Path=/liveness; Max-Age=60; Secure; HttpOnly; SameSite=Strict');
});

test('__Host- cookies must use Path=/', () => {
  assert.throws(() => serializeCookie('__Host-x', 'v', { path: '/liveness' }));
});

test('cookie values outside the token alphabet are refused', () => {
  assert.throws(() => serializeCookie('a', 'v; Domain=evil.example'));
});

test('parseCookies reads every Cookie header and keeps the first duplicate', () => {
  const cookies = parseCookies({ cookie: [{ value: 'a=1; b=2' }, { value: 'a=3; c=4' }] });
  assert.deepEqual(cookies, { a: '1', b: '2', c: '4' });
});

test('safeRelativePath only allows same-origin paths', () => {
  assert.equal(safeRelativePath('/checkout.html?event=jazz'), '/checkout.html?event=jazz');
  for (const bad of ['//evil.example', '/\\evil.example', 'https://evil.example', 'evil', '/a\nb', '/a\\b', undefined]) {
    assert.equal(safeRelativePath(bad), '/', String(bad));
  }
});
