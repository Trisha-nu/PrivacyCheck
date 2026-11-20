'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, summarise, parseCookie, TESTS } = require('../lib/checks');

const good = () => ({
  finalUrl: 'https://example.test/', status: 200, contentType: 'text/html',
  headers: {
    'strict-transport-security': 'max-age=31536000', 'content-security-policy': "default-src 'self'",
    'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer'
  },
  setCookies: ['sid=1; Secure; HttpOnly; SameSite=Lax'],
  body: '<a href="/privacy">Privacy</a><div class="cookie-banner">We use cookies</div>'
});
const status = (obs, id) => evaluate(obs).find((r) => r.id === id).status;

test('a fully hardened site passes every test case', () => {
  const r = evaluate(good());
  assert.equal(r.length, TESTS.length);
  assert.ok(r.every((x) => x.status === 'pass'), JSON.stringify(r.filter((x) => x.status !== 'pass')));
  assert.equal(summarise(r).score, 100);
});

test('TC01 fails over http and passes over https', () => {
  assert.equal(status({ ...good(), finalUrl: 'http://example.test/' }, 'TC01'), 'fail');
  assert.equal(status(good(), 'TC01'), 'pass');
});

test('TC02 fails when HSTS missing or max-age is zero', () => {
  const o = good(); delete o.headers['strict-transport-security'];
  assert.equal(status(o, 'TC02'), 'fail');
  o.headers['strict-transport-security'] = 'max-age=0';
  assert.equal(status(o, 'TC02'), 'fail');
});

test('TC03 treats Report-Only CSP as a failure', () => {
  const o = good(); delete o.headers['content-security-policy'];
  o.headers['content-security-policy-report-only'] = "default-src 'self'";
  assert.equal(status(o, 'TC03'), 'fail');
});

test('TC05 accepts CSP frame-ancestors as an alternative to X-Frame-Options', () => {
  const o = good(); delete o.headers['x-frame-options'];
  o.headers['content-security-policy'] = "frame-ancestors 'none'";
  assert.equal(status(o, 'TC05'), 'pass');
});

test('TC06 fails on unsafe-url', () => {
  const o = good(); o.headers['referrer-policy'] = 'unsafe-url';
  assert.equal(status(o, 'TC06'), 'fail');
});

test('cookie checks are inconclusive when no cookies are set', () => {
  const o = { ...good(), setCookies: [] };
  ['TC07', 'TC08', 'TC09'].forEach((id) => assert.equal(status(o, id), 'inconclusive'));
});

test('cookie checks fail if any one cookie lacks the attribute', () => {
  const o = { ...good(), setCookies: ['a=1; Secure; HttpOnly; SameSite=Lax', 'b=2'] };
  ['TC07', 'TC08', 'TC09'].forEach((id) => assert.equal(status(o, id), 'fail'));
});

test('parseCookie reads attributes case-insensitively', () => {
  assert.deepEqual(parseCookie('id=9; SECURE; httponly; SameSite=Strict'), { name: 'id', secure: true, httpOnly: true, sameSite: 'strict' });
});

test('TC10 fails when no privacy link exists and passes on link text match', () => {
  assert.equal(status({ ...good(), body: '<a href="/about">About</a>' }, 'TC10'), 'fail');
  assert.equal(status({ ...good(), body: '<a href="/legal">Privacy Policy</a>' }, 'TC10'), 'pass');
});

test('TC11 is inconclusive, not fail, when no consent markup is visible', () => {
  assert.equal(status({ ...good(), body: '<a href="/privacy">Privacy</a>' }, 'TC11'), 'inconclusive');
});

test('non-HTML responses make page-content checks inconclusive', () => {
  const o = { ...good(), contentType: 'application/json', body: '{}' };
  assert.equal(status(o, 'TC10'), 'inconclusive');
  assert.equal(status(o, 'TC11'), 'inconclusive');
});

test('blocked (403) responses: only HTTPS is decided, everything else inconclusive', () => {
  const r = evaluate({ ...good(), status: 403 });
  assert.equal(r[0].status, 'pass');
  assert.ok(r.slice(1).every((x) => x.status === 'inconclusive'));
});

test('network errors never invent results', () => {
  const r = evaluate({ error: 'ENOTFOUND', finalUrl: null, headers: {}, setCookies: [] });
  assert.ok(r.every((x) => x.status === 'inconclusive'));
  assert.equal(summarise(r).score, null);
});
