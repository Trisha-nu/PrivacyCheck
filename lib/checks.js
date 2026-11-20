'use strict';
/**
 * The rule set. Every test case is a pure function of an "observation"
 * (what was actually retrieved from a site) and returns one of:
 *   pass | fail | inconclusive
 * A check returns "inconclusive" whenever the evidence is not sufficient,
 * so the report never invents a result.
 */

const TESTS = [
  { id: 'TC01', name: 'HTTPS is used', category: 'Transport', severity: 'High',
    description: 'The final page is delivered over an encrypted HTTPS connection.',
    fix: 'Serve the site over HTTPS and redirect all HTTP traffic to it.' },
  { id: 'TC02', name: 'HSTS header present', category: 'Transport', severity: 'Medium',
    description: 'Strict-Transport-Security tells browsers to always use HTTPS.',
    fix: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { id: 'TC03', name: 'Content-Security-Policy present', category: 'Headers', severity: 'High',
    description: 'A CSP limits where scripts and other resources can load from.',
    fix: "Add a Content-Security-Policy header, e.g. default-src 'self'." },
  { id: 'TC04', name: 'MIME sniffing blocked', category: 'Headers', severity: 'Low',
    description: 'X-Content-Type-Options: nosniff stops browsers guessing content types.',
    fix: 'Add X-Content-Type-Options: nosniff' },
  { id: 'TC05', name: 'Clickjacking protection', category: 'Headers', severity: 'Medium',
    description: 'X-Frame-Options or CSP frame-ancestors prevents the page being framed.',
    fix: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'." },
  { id: 'TC06', name: 'Referrer-Policy present', category: 'Headers', severity: 'Low',
    description: 'Controls how much URL information is leaked to other sites.',
    fix: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
  { id: 'TC07', name: 'Cookies use Secure', category: 'Cookies', severity: 'High',
    description: 'Every cookie set by the response carries the Secure attribute.',
    fix: 'Add the Secure attribute to all Set-Cookie headers.' },
  { id: 'TC08', name: 'Cookies use HttpOnly', category: 'Cookies', severity: 'Medium',
    description: 'Every cookie set by the response carries the HttpOnly attribute.',
    fix: 'Add HttpOnly to cookies that scripts do not need to read.' },
  { id: 'TC09', name: 'Cookies declare SameSite', category: 'Cookies', severity: 'Medium',
    description: 'Every cookie set by the response declares a SameSite policy.',
    fix: 'Add SameSite=Lax (or Strict) to all cookies.' },
  { id: 'TC10', name: 'Privacy notice discoverable', category: 'Privacy', severity: 'High',
    description: 'A link to a privacy policy can be found in the page HTML.',
    fix: 'Link to a privacy policy from every page, typically in the footer.' },
  { id: 'TC11', name: 'Cookie consent mechanism detected', category: 'Privacy', severity: 'Medium',
    description: 'Consent banner markup is present in the static page HTML.',
    fix: 'Show a cookie consent notice before non-essential cookies are set.' }
];

const BLOCKED_STATUS = (s) => s >= 400;

function res(test, status, evidence) {
  return {
    id: test.id, name: test.name, category: test.category, severity: test.severity,
    description: test.description, fix: test.fix, status, evidence
  };
}

function parseCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const [name] = parts[0].split('=');
  const attrs = parts.slice(1).map((p) => p.toLowerCase());
  return {
    name,
    secure: attrs.includes('secure'),
    httpOnly: attrs.includes('httponly'),
    sameSite: (attrs.find((a) => a.startsWith('samesite=')) || '').split('=')[1] || null
  };
}

function isHtml(obs) {
  return typeof obs.body === 'string' && /html/i.test(obs.contentType || '');
}

function cookieCheck(test, cookies, pred, label) {
  if (!cookies.length) return res(test, 'inconclusive', 'No cookies were set by this response, so there is nothing to test.');
  const bad = cookies.filter((c) => !pred(c)).map((c) => c.name);
  if (bad.length) return res(test, 'fail', `${bad.length} of ${cookies.length} cookie(s) missing ${label}: ${bad.join(', ')}`);
  return res(test, 'pass', `All ${cookies.length} cookie(s) set ${label}: ${cookies.map((c) => c.name).join(', ')}`);
}

function evaluate(obs) {
  const T = Object.fromEntries(TESTS.map((t) => [t.id, t]));
  const out = [];
  const h = obs.headers || {};

  if (obs.error && !obs.finalUrl) {
    return TESTS.map((t) => res(t, 'inconclusive', `Site could not be retrieved: ${obs.error}`));
  }
  // The URL scheme alone decides HTTPS, so this check still works on a blocked page.
  const https = /^https:/i.test(obs.finalUrl || '');
  out.push(res(T.TC01, https ? 'pass' : 'fail',
    https ? `Final URL uses HTTPS (${obs.finalUrl}).` : `Final URL uses plain HTTP (${obs.finalUrl}).`));

  if (obs.error || BLOCKED_STATUS(obs.status)) {
    const why = obs.error ? `Request failed: ${obs.error}` : `Server answered HTTP ${obs.status}; automated access appears to be blocked.`;
    TESTS.slice(1).forEach((t) => out.push(res(t, 'inconclusive', why)));
    return out;
  }

  const hsts = h['strict-transport-security'];
  const maxAge = hsts && /max-age=(\d+)/i.exec(hsts);
  if (!hsts) out.push(res(T.TC02, 'fail', 'Strict-Transport-Security header not found.'));
  else if (!maxAge || Number(maxAge[1]) <= 0) out.push(res(T.TC02, 'fail', `HSTS present but max-age is missing or zero: ${hsts}`));
  else out.push(res(T.TC02, 'pass', `Found: ${hsts}`));

  const csp = h['content-security-policy'];
  if (csp && csp.trim()) out.push(res(T.TC03, 'pass', `Found: ${csp.slice(0, 160)}`));
  else if (h['content-security-policy-report-only']) out.push(res(T.TC03, 'fail', 'Only a Report-Only policy was found; it is not enforced.'));
  else out.push(res(T.TC03, 'fail', 'Content-Security-Policy header not found.'));

  const nosniff = (h['x-content-type-options'] || '').toLowerCase();
  out.push(res(T.TC04, nosniff === 'nosniff' ? 'pass' : 'fail',
    nosniff === 'nosniff' ? 'Found: X-Content-Type-Options: nosniff' : 'X-Content-Type-Options: nosniff not found.'));

  const xfo = (h['x-frame-options'] || '').toLowerCase();
  const fa = /frame-ancestors/i.test(csp || '');
  if (['deny', 'sameorigin'].includes(xfo)) out.push(res(T.TC05, 'pass', `Found: X-Frame-Options: ${xfo.toUpperCase()}`));
  else if (fa) out.push(res(T.TC05, 'pass', 'Found CSP frame-ancestors directive.'));
  else out.push(res(T.TC05, 'fail', 'Neither X-Frame-Options nor CSP frame-ancestors found.'));

  const rp = (h['referrer-policy'] || '').toLowerCase();
  if (!rp) out.push(res(T.TC06, 'fail', 'Referrer-Policy header not found.'));
  else if (rp === 'unsafe-url') out.push(res(T.TC06, 'fail', 'Referrer-Policy is unsafe-url, which leaks full URLs.'));
  else out.push(res(T.TC06, 'pass', `Found: Referrer-Policy: ${rp}`));

  const cookies = (obs.setCookies || []).map(parseCookie);
  out.push(cookieCheck(T.TC07, cookies, (c) => c.secure, 'Secure'));
  out.push(cookieCheck(T.TC08, cookies, (c) => c.httpOnly, 'HttpOnly'));
  out.push(cookieCheck(T.TC09, cookies, (c) => !!c.sameSite, 'SameSite'));

  if (!isHtml(obs)) {
    out.push(res(T.TC10, 'inconclusive', 'Response is not an HTML page, so links cannot be inspected.'));
    out.push(res(T.TC11, 'inconclusive', 'Response is not an HTML page, so consent markup cannot be inspected.'));
  } else {
    const anchors = [...obs.body.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)];
    const hit = anchors.find((m) => /privacy|data-protection|gdpr/i.test(m[1]) || /privacy|data protection/i.test(m[2].replace(/<[^>]+>/g, '')));
    out.push(hit
      ? res(T.TC10, 'pass', `Privacy link found: ${hit[1]}`)
      : res(T.TC10, 'fail', `No privacy-policy link among ${anchors.length} link(s) in the static HTML. Links added by JavaScript are not visible to this check.`));

    const consent = /cookie[-_ ]?(consent|banner|notice|settings)|accept (all )?cookies|we use cookies|onetrust|cookiebot|cmp-/i.test(obs.body);
    out.push(consent
      ? res(T.TC11, 'pass', 'Consent banner markup found in the page HTML.')
      : res(T.TC11, 'inconclusive', 'No consent markup in static HTML. It may be injected by JavaScript; a real-browser check is needed to be sure.'));
  }
  return out;
}

function summarise(results) {
  const c = { pass: 0, fail: 0, inconclusive: 0 };
  results.forEach((r) => { c[r.status] += 1; });
  const decided = c.pass + c.fail;
  return { ...c, total: results.length, score: decided ? Math.round((c.pass / decided) * 100) : null };
}

module.exports = { TESTS, evaluate, summarise, parseCookie };
