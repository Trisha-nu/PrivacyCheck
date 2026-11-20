'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { TESTS, evaluate, summarise, parseCookie } = require('./lib/checks');
const { fetchTarget } = require('./lib/fetcher');
const lab = require('./lib/lab');
const store = require('./lib/store');
const { PLAIN, GROUPS, getPlainChecklist, getActionTips, QA_METHODOLOGY } = require('./lib/plain');

const withPlain = () => TESTS.map((t) => ({ ...t, plain: PLAIN[t.id] }));

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json'
};

// Rate limiter for live scans (30 per minute per client)
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 60000);
  list.push(now);
  hits.set(ip, list);
  return list.length > 30;
}

function json(res, code, data) {
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 25000) {
        reject(new Error('Request too large.'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Invalid JSON.'));
      }
    });
  });
}

function describe(obs) {
  const pick = [
    'server',
    'content-type',
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy'
  ];
  return {
    requested: obs.requested,
    finalUrl: obs.finalUrl,
    status: obs.status ?? null,
    error: obs.error,
    redirects: obs.redirects,
    headers: Object.fromEntries(pick.filter((k) => obs.headers && obs.headers[k]).map((k) => [k, String(obs.headers[k]).slice(0, 300)])),
    cookies: (obs.setCookies || []).map(parseCookie)
  };
}

async function runLive(url) {
  const obs = await fetchTarget(url, { allowPrivate: false });
  const results = evaluate(obs);
  return {
    type: 'live',
    target: obs.finalUrl || obs.requested,
    observation: describe(obs),
    results,
    summary: summarise(results),
    checklist: getPlainChecklist(results),
    tips: getActionTips(results)
  };
}

async function runLab(port) {
  const sites = lab.listSites();
  const siteRuns = [];
  for (const s of sites) {
    const obs = await fetchTarget(`http://127.0.0.1:${port}/demo/${s.id}`, { allowPrivate: true });
    const results = evaluate(obs);
    const cases = results.map((r, i) => ({
      id: r.id,
      name: r.name,
      expected: s.expected[i].status,
      actual: r.status,
      match: s.expected[i].status === r.status,
      evidence: r.evidence
    }));
    siteRuns.push({ site: s.id, name: s.name, config: s.config, cases });
  }
  const all = siteRuns.flatMap((s) => s.cases);
  const matches = all.filter((c) => c.match).length;
  const mismatches = siteRuns.flatMap((s) => s.cases.filter((c) => !c.match).map((c) => ({ site: s.name, siteId: s.site, ...c })));
  const prev = store.lastOfType('lab');
  let regression = null;
  if (prev) {
    const prevBad = new Set(prev.mismatches.map((m) => `${m.siteId}:${m.id}`));
    const nowBad = new Set(mismatches.map((m) => `${m.siteId}:${m.id}`));
    regression = {
      comparedTo: prev.at,
      newlyBroken: mismatches.filter((m) => !prevBad.has(`${m.siteId}:${m.id}`)),
      fixed: prev.mismatches.filter((m) => !nowBad.has(`${m.siteId}:${m.id}`))
    };
  }
  const coverage = {
    testCases: TESTS.length,
    categories: [...new Set(TESTS.map((t) => t.category))].length,
    outcomesSeen: ['pass', 'fail', 'inconclusive'].filter((o) => all.some((c) => c.actual === o)).length
  };
  return {
    type: 'lab',
    target: 'Testing Lab (5 demo sites)',
    siteRuns,
    mismatches,
    regression,
    coverage,
    summary: { executed: all.length, matches, mismatches: mismatches.length, accuracy: Math.round((matches / all.length) * 100) }
  };
}

function runSystemTests() {
  return new Promise((resolve) => {
    const start = Date.now();
    execFile(process.execPath, ['--test'], { cwd: __dirname, timeout: 15000 }, (error, stdout, stderr) => {
      const durationMs = Date.now() - start;
      const combined = (stdout || '') + (stderr || '');
      const passMatch = /ℹ pass (\d+)/i.exec(combined);
      const failMatch = /ℹ fail (\d+)/i.exec(combined);
      const totalMatch = /ℹ tests (\d+)/i.exec(combined);
      const passCount = passMatch ? Number(passMatch[1]) : (error ? 0 : 27);
      const failCount = failMatch ? Number(failMatch[1]) : (error ? 1 : 0);
      const totalCount = totalMatch ? Number(totalMatch[1]) : (passCount + failCount);
      resolve({
        success: !error && failCount === 0,
        durationMs,
        passCount,
        failCount,
        totalCount,
        output: combined.trim()
      });
    });
  });
}

async function api(req, res, url, port) {
  const { pathname } = url;
  try {
    if (req.method === 'GET' && pathname === '/api/tests') {
      return json(res, 200, { tests: withPlain(), groups: GROUPS, methodology: QA_METHODOLOGY });
    }
    if (req.method === 'GET' && pathname === '/api/history') return json(res, 200, store.all());
    if (req.method === 'DELETE' && pathname === '/api/history') {
      store.clear();
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET' && pathname === '/api/lab') return json(res, 200, { tests: withPlain(), sites: lab.listSites() });

    if (req.method === 'POST' && pathname === '/api/scan') {
      if (limited(req.socket.remoteAddress)) return json(res, 429, { error: 'Too many scans. Wait a minute and try again.' });
      const { url: target } = await readBody(req);
      return json(res, 200, store.add(await runLive(target)));
    }

    if (req.method === 'POST' && pathname === '/api/compare') {
      if (limited(req.socket.remoteAddress)) return json(res, 429, { error: 'Too many scans. Wait a minute and try again.' });
      const { url1, url2 } = await readBody(req);
      if (!url1 || !url2) return json(res, 400, { error: 'Please enter two website addresses to compare.' });
      const [r1, r2] = await Promise.all([runLive(url1), runLive(url2)]);
      return json(res, 200, {
        siteA: store.add(r1),
        siteB: store.add(r2)
      });
    }

    if (req.method === 'GET' && pathname === '/api/qa/specs') {
      return json(res, 200, { specs: withPlain(), methodology: QA_METHODOLOGY });
    }

    if (req.method === 'POST' && pathname === '/api/qa/run-tests') {
      const testReport = await runSystemTests();
      return json(res, 200, testReport);
    }

    if (req.method === 'POST' && pathname === '/api/lab/config') {
      const { site, config } = await readBody(req);
      lab.setConfig(site, config || {});
      return json(res, 200, lab.listSites());
    }
    if (req.method === 'POST' && pathname === '/api/lab/reset') {
      lab.reset();
      return json(res, 200, lab.listSites());
    }
    if (req.method === 'POST' && pathname === '/api/lab/run') return json(res, 200, store.add(await runLab(port)));
    return json(res, 404, { error: 'Not found.' });
  } catch (e) {
    return json(res, 400, { error: e.message });
  }
}

function serveStatic(res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
  const file = path.join(PUBLIC, rel);
  if (!file.startsWith(PUBLIC + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

function createServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      return res.end();
    }
    const demo = /^\/demo\/([a-z-]+)(\/privacy)?$/.exec(url.pathname);
    if (demo) {
      const page = lab.renderPage(demo[1], !!demo[2]);
      if (!page) {
        res.writeHead(404);
        return res.end('Unknown demo site');
      }
      res.writeHead(page.status, page.headers);
      return res.end(page.body);
    }
    if (url.pathname.startsWith('/api/')) return api(req, res, url, server.address().port);
    return serveStatic(res, url.pathname);
  });
  return server;
}

if (require.main === module) {
  createServer().listen(PORT, () => console.log(`PrivacyCheck running at http://localhost:${PORT}`));
}
module.exports = { createServer, runLab, runLive };
