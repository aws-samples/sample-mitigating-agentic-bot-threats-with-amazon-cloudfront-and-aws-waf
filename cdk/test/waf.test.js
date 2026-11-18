'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isFlagged, wafTokenId } = require('../lambda/edge/lib/waf');
const { cfEvent } = require('./helpers');

const headersOf = (headers) => cfEvent({ headers }).Records[0].cf.request.headers;

test('isFlagged reads the header AWS WAF inserts', () => {
  assert.equal(isFlagged(headersOf({ 'x-amzn-waf-bot-suspect': 'true' })), true);
  assert.equal(isFlagged(headersOf({ 'x-amzn-waf-bot-suspect': 'TRUE' })), true);
  assert.equal(isFlagged(headersOf({ 'x-amzn-waf-bot-suspect': 'false' })), false);
  assert.equal(isFlagged(headersOf({})), false);
});

test('wafTokenId returns the forwarded token ID', () => {
  assert.equal(wafTokenId(headersOf({ 'x-amzn-waf-token-id': '  abc-123  ' })), 'abc-123');
});

test('wafTokenId treats missing, empty, oversized, multi-valued, or repeated headers as no token', () => {
  assert.equal(wafTokenId(headersOf({})), null);
  assert.equal(wafTokenId(headersOf({ 'x-amzn-waf-token-id': '' })), null);
  assert.equal(wafTokenId(headersOf({ 'x-amzn-waf-token-id': 'x'.repeat(513) })), null);
  // Interpolation joins several labels with commas; a request has one token.
  assert.equal(wafTokenId(headersOf({ 'x-amzn-waf-token-id': 'a,b' })), null);
  assert.equal(wafTokenId(headersOf({ 'x-amzn-waf-token-id': ['a', 'b'] })), null);
});
