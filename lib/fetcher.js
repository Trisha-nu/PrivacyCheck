'use strict';
/**
 * Safe page fetcher with SSRF protection.
 * - only http/https, only ports 80/443 for public scans
 * - destination IPs are validated at connect time (defeats DNS rebinding)
 * - redirects are followed manually and re-validated at every hop
 * - strict timeout and body-size limit
 */
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');

const MAX_BODY = 512 * 1024;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 10000;
const UA = 'PrivacyCheck/1.0 (educational testing tool)';

function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(l);
    if (mapped) return isPrivateIPv4(mapped[1]);
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') ||
      l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') || l.startsWith('ff');
  }
  return true;
}

function normaliseUrl(input) {
  let s = String(input || '').trim();
  if (!s) throw new Error('Enter a website address.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u;
  try { u = new URL(s); } catch { throw new Error('That does not look like a valid web address.'); }
  return u;
}

function validateUrl(u, allowPrivate) {
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http and https addresses can be checked.');
  if (u.username || u.password) throw new Error('Addresses containing credentials are not allowed.');
  if (allowPrivate) return;
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  if (!['80', '443'].includes(port)) throw new Error('Only standard web ports (80 and 443) can be checked.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && isPrivateIp(host)) throw new Error('Blocked: private and internal addresses cannot be checked.');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Blocked: private and internal addresses cannot be checked.');
  }
}

function guardedLookup(allowPrivate) {
  return (hostname, options, cb) => {
    if (typeof options === 'function') { cb = options; options = {}; }
    dns.lookup(hostname, { all: true, family: options.family || 0 }, (err, addrs) => {
      if (err) return cb(err);
      if (!allowPrivate && addrs.some((a) => isPrivateIp(a.address))) {
        return cb(new Error('Blocked: destination resolves to a private or internal address.'));
      }
      if (options.all) return cb(null, addrs);
      return cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

function requestOnce(u, allowPrivate) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, {
      method: 'GET',
      lookup: guardedLookup(allowPrivate),
      headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5', 'Accept-Encoding': 'identity' },
      timeout: TIMEOUT_MS
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size <= MAX_BODY) chunks.push(c);
        else res.destroy();
      });
      const done = () => resolve({
        status: res.statusCode,
        headers: Object.fromEntries(Object.entries(res.headers).filter(([k]) => k !== 'set-cookie')),
        setCookies: res.headers['set-cookie'] || [],
        body: Buffer.concat(chunks).toString('utf8')
      });
      res.on('end', done);
      res.on('close', done);
    });
    req.on('timeout', () => req.destroy(new Error('Request timed out after 10 seconds.')));
    req.on('error', reject);
    req.end();
  });
}

/** Fetch a site and return an observation object for the checks engine. */
async function fetchTarget(input, { allowPrivate = false } = {}) {
  let u = normaliseUrl(input);
  const redirects = [];
  const cookies = [];
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    validateUrl(u, allowPrivate);
    let r;
    try {
      r = await requestOnce(u, allowPrivate);
    } catch (e) {
      return { finalUrl: redirects.length ? u.href : null, requested: String(input), error: e.message, redirects, setCookies: cookies, headers: {}, body: null };
    }
    cookies.push(...r.setCookies);
    const loc = r.headers.location;
    if ([301, 302, 303, 307, 308].includes(r.status) && loc) {
      redirects.push({ from: u.href, status: r.status, to: new URL(loc, u).href });
      u = new URL(loc, u);
      continue;
    }
    return {
      requested: String(input), finalUrl: u.href, status: r.status, headers: r.headers,
      contentType: r.headers['content-type'] || '', setCookies: cookies, body: r.body, redirects, error: null
    };
  }
  return { requested: String(input), finalUrl: u.href, error: `Too many redirects (more than ${MAX_REDIRECTS}).`, redirects, setCookies: cookies, headers: {}, body: null };
}

module.exports = { fetchTarget, isPrivateIp, normaliseUrl, validateUrl };
