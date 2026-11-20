'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isPrivateIp, normaliseUrl, validateUrl, fetchTarget } = require('../lib/fetcher');

test('private, loopback, link-local and reserved IPs are recognised', () => {
  ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']
    .forEach((ip) => assert.equal(isPrivateIp(ip), true, ip));
});

test('public IPs are allowed', () => {
  ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111'].forEach((ip) => assert.equal(isPrivateIp(ip), false, ip));
});

test('validateUrl blocks internal hosts, odd ports, other schemes and credentials', () => {
  const bad = ['http://127.0.0.1/', 'http://localhost/', 'http://169.254.169.254/latest/meta-data', 'https://example.com:8443/', 'http://[::1]/', 'ftp://example.com/', 'https://user:pw@example.com/', 'http://printer.local/'];
  bad.forEach((s) => assert.throws(() => validateUrl(new URL(s), false), Error, s));
});

test('validateUrl allows normal public sites', () => {
  assert.doesNotThrow(() => validateUrl(new URL('https://example.com/'), false));
});

test('normaliseUrl adds https and rejects empty or invalid input', () => {
  assert.equal(normaliseUrl('example.com').href, 'https://example.com/');
  assert.throws(() => normaliseUrl('   '));
  assert.throws(() => normaliseUrl('http://'));
});

test('fetchTarget refuses an internal address before connecting', async () => {
  await assert.rejects(fetchTarget('http://127.0.0.1:3000/'), /private|standard web ports/i);
});
