'use strict';
/**
 * Testing Lab: controlled demo sites with KNOWN configurations and a
 * hand-written expected-results oracle. The oracle is deliberately NOT derived
 * from the same code that runs the checks, so a mismatch means a real defect
 * (or a deliberate configuration change = a regression).
 *
 * Expected string order follows TC01..TC11. P = pass, F = fail, I = inconclusive.
 * TC01 expects F everywhere because the demo sites are served over local HTTP.
 */
const { TESTS } = require('./checks');

const CODE = { P: 'pass', F: 'fail', I: 'inconclusive' };

const SITES = [
  {
    id: 'secure-shop', name: 'Secure Shop',
    blurb: 'Fully hardened: every header, safe cookies, privacy link and consent banner.',
    config: { status: 200, hsts: true, csp: true, nosniff: true, xfo: true, referrer: true, cookie: true, cookieSecure: true, cookieHttpOnly: true, cookieSameSite: true, privacyLink: true, banner: true },
    expected: 'FPPPPPPPPPP'
  },
  {
    id: 'bare-blog', name: 'Bare Blog',
    blurb: 'No security headers, no cookies, no privacy link, no banner.',
    config: { status: 200, hsts: false, csp: false, nosniff: false, xfo: false, referrer: false, cookie: false, cookieSecure: false, cookieHttpOnly: false, cookieSameSite: false, privacyLink: false, banner: false },
    expected: 'FFFFFFIIIFI'
  },
  {
    id: 'loose-cookies', name: 'Loose Cookies',
    blurb: 'Some headers set, but the session cookie has no protective attributes.',
    config: { status: 200, hsts: true, csp: false, nosniff: true, xfo: true, referrer: false, cookie: true, cookieSecure: false, cookieHttpOnly: false, cookieSameSite: false, privacyLink: true, banner: true },
    expected: 'FPFPPFFFFPP'
  },
  {
    id: 'half-done', name: 'Half Done',
    blurb: 'Good CSP and cookies, but no privacy link and weak SameSite handling.',
    config: { status: 200, hsts: false, csp: true, nosniff: true, xfo: false, referrer: true, cookie: true, cookieSecure: true, cookieHttpOnly: true, cookieSameSite: false, privacyLink: false, banner: true },
    expected: 'FFPPFPPPFFP'
  },
  {
    id: 'blocked-site', name: 'Blocked Site',
    blurb: 'Answers HTTP 403, like a site that refuses automated access.',
    config: { status: 403, hsts: false, csp: false, nosniff: false, xfo: false, referrer: false, cookie: false, cookieSecure: false, cookieHttpOnly: false, cookieSameSite: false, privacyLink: false, banner: false },
    expected: 'FIIIIIIIIII'
  }
];

const state = {};
function reset() { SITES.forEach((s) => { state[s.id] = { ...s.config }; }); }
reset();

function expectedFor(id) {
  const site = SITES.find((s) => s.id === id);
  return [...site.expected].map((c, i) => ({ id: TESTS[i].id, status: CODE[c] }));
}

function listSites() {
  return SITES.map((s) => ({ id: s.id, name: s.name, blurb: s.blurb, baseline: s.config, config: state[s.id], expected: expectedFor(s.id) }));
}

function setConfig(id, patch) {
  if (!state[id]) throw new Error('Unknown demo site.');
  const allowed = Object.keys(SITES[0].config).filter((k) => k !== 'status');
  allowed.forEach((k) => { if (typeof patch[k] === 'boolean') state[id][k] = patch[k]; });
  return state[id];
}

function renderPage(id, privacy) {
  const site = SITES.find((s) => s.id === id);
  const c = state[id];
  if (!site) return null;
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  if (c.status !== 200) return { status: c.status, headers, body: '<h1>Access denied</h1><p>Automated clients are not permitted.</p>' };
  if (c.hsts) headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  if (c.csp) headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:";
  if (c.nosniff) headers['X-Content-Type-Options'] = 'nosniff';
  if (c.xfo) headers['X-Frame-Options'] = 'DENY';
  if (c.referrer) headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
  if (c.cookie) {
    const attrs = ['Path=/'];
    if (c.cookieSecure) attrs.push('Secure');
    if (c.cookieHttpOnly) attrs.push('HttpOnly');
    if (c.cookieSameSite) attrs.push('SameSite=Lax');
    headers['Set-Cookie'] = [`sid=demo-${id}; ${attrs.join('; ')}`];
  }
  const body = privacy
    ? `<!doctype html><title>Privacy policy</title><h1>Privacy policy</h1><p>Demo page for ${site.name}.</p>`
    : `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${site.name}</title></head><body>
<h1>${site.name}</h1><p>${site.blurb}</p><p>This is a controlled demo page used to test PrivacyCheck.</p>
${c.banner ? '<div id="cookie-banner" class="cookie-consent">We use cookies to improve your visit. <button>Accept all cookies</button></div>' : ''}
<footer><a href="/about">About</a> <a href="/contact">Contact</a>${c.privacyLink ? ` <a href="/demo/${id}/privacy">Privacy Policy</a>` : ''}</footer></body></html>`;
  return { status: 200, headers, body };
}

module.exports = { SITES, listSites, setConfig, reset, renderPage, expectedFor };
