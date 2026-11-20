'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getPlainChecklist, getActionTips, QA_METHODOLOGY } = require('../lib/plain');
const { evaluate, summarise } = require('../lib/checks');
const { createServer } = require('../server');

const mockObs = (overrides = {}) => ({
  finalUrl: 'https://example.test/',
  status: 200,
  contentType: 'text/html',
  headers: {
    'strict-transport-security': 'max-age=31536000',
    'content-security-policy': "default-src 'self'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin'
  },
  setCookies: ['sid=demo; Secure; HttpOnly; SameSite=Lax'],
  body: '<a href="/privacy">Privacy Policy</a><div class="cookie-banner">We use cookies</div>',
  ...overrides
});

test('getPlainChecklist approves safe logins and payments on fully hardened site', () => {
  const results = evaluate(mockObs());
  const list = getPlainChecklist(results);
  assert.equal(list.length, 5);
  const login = list.find((item) => item.id === 'login');
  assert.equal(login.status, 'pass');
  assert.match(login.label, /Safe to Log In/i);

  const pay = list.find((item) => item.id === 'pay');
  assert.equal(pay.status, 'pass');
  assert.match(pay.label, /Safe for Payments/i);
});

test('getPlainChecklist flags insecure logins when HTTPS fails', () => {
  const results = evaluate(mockObs({ finalUrl: 'http://insecure.test/' }));
  const list = getPlainChecklist(results);
  const login = list.find((item) => item.id === 'login');
  assert.equal(login.status, 'fail');
  assert.match(login.reason, /unencrypted/i);

  const wifi = list.find((item) => item.id === 'wifi');
  assert.equal(wifi.status, 'fail');
});

test('getActionTips provides actionable guidance based on failed checks', () => {
  const badSite = mockObs({
    finalUrl: 'http://insecure.test/',
    headers: {},
    setCookies: ['sid=123'] // missing Secure & HttpOnly
  });
  const results = evaluate(badSite);
  const tips = getActionTips(results);
  assert.ok(tips.length > 0);
  assert.ok(tips.some((t) => /confidential|passwords/i.test(t.title + t.desc)));
  assert.ok(tips.some((t) => /log out/i.test(t.title + t.desc)));
});

test('getActionTips returns positive endorsement when site is fully compliant', () => {
  const cleanSite = mockObs();
  const results = evaluate(cleanSite);
  const tips = getActionTips(results);
  assert.equal(tips.length, 1);
  assert.match(tips[0].title, /top-tier safety/i);
});

test('QA methodology provides testing principles for CSA3701', () => {
  assert.ok(QA_METHODOLOGY.keyPrinciples.length >= 4);
  assert.ok(QA_METHODOLOGY.keyPrinciples.some((p) => /Oracle/i.test(p.name)));
});

let server, port;
test.before(async () => {
  server = createServer();
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});
test.after(() => server.close());

test('API GET /api/qa/specs returns test case specifications and ISO 25010 data', async () => {
  const res = await fetch(`http://127.0.0.1:${port}/api/qa/specs`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.specs.length, 11);
  assert.ok(data.specs[0].plain.iso25010);
  assert.ok(data.methodology);
});

test('API POST /api/qa/run-tests executes unit test suite and reports pass metrics', async () => {
  const res = await fetch(`http://127.0.0.1:${port}/api/qa/run-tests`, { method: 'POST' });
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(typeof data.passCount, 'number');
  assert.ok(data.passCount >= 27);
  assert.equal(data.failCount, 0);
  assert.equal(data.success, true);
});

test('API POST /api/compare returns validation error on missing inputs', async () => {
  const res = await fetch(`http://127.0.0.1:${port}/api/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url1: 'https://example.com' })
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /two website addresses/i);
});
