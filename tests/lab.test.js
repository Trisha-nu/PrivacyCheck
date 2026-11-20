'use strict';
// Integration test: runs the real server, the full lab suite, and a regression scenario.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createServer, runLab } = require('../server');
const lab = require('../lib/lab');

let server, port;
test.before(async () => { server = createServer(); await new Promise((r) => server.listen(0, r)); port = server.address().port; });
test.after(() => server.close());

test('baseline lab run matches the expected-results oracle exactly', async () => {
  lab.reset();
  const run = await runLab(port);
  assert.equal(run.summary.executed, 55);
  assert.deepEqual(run.mismatches, []);
  assert.equal(run.summary.accuracy, 100);
});

test('all three outcomes (pass, fail, inconclusive) are exercised by the lab', async () => {
  lab.reset();
  assert.equal((await runLab(port)).coverage.outcomesSeen, 3);
});

test('removing CSP from the secure site is caught as a regression on TC03', async () => {
  lab.reset();
  lab.setConfig('secure-shop', { csp: false });
  const run = await runLab(port);
  assert.deepEqual(run.mismatches.map((m) => `${m.siteId}:${m.id}`), ['secure-shop:TC03']);
  lab.reset();
});

test('dropping Secure from cookies is caught on TC07 only', async () => {
  lab.reset();
  lab.setConfig('secure-shop', { cookieSecure: false });
  const run = await runLab(port);
  assert.deepEqual(run.mismatches.map((m) => m.id), ['TC07']);
  lab.reset();
});

test('demo pages expose the headers their configuration promises', async () => {
  lab.reset();
  const r = await fetch(`http://127.0.0.1:${port}/demo/secure-shop`);
  assert.equal(r.status, 200);
  assert.ok(r.headers.get('content-security-policy'));
  const blocked = await fetch(`http://127.0.0.1:${port}/demo/blocked-site`);
  assert.equal(blocked.status, 403);
});

test('live scan endpoint rejects internal targets (SSRF)', async () => {
  const r = await fetch(`http://127.0.0.1:${port}/api/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://169.254.169.254/' }) });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /private|internal|ports/i);
});

test('static file serving blocks path traversal', async () => {
  const r = await fetch(`http://127.0.0.1:${port}/..%2f..%2fpackage.json`);
  assert.notEqual(r.status, 200);
});
