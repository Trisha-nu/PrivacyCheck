'use strict';
const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'data', 'history.json');
const LIMIT = 100;

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { return []; }
}
function save(list) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(list.slice(0, LIMIT), null, 2));
}
function add(run) {
  const list = load();
  const entry = { id: `run-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`, at: new Date().toISOString(), ...run };
  list.unshift(entry);
  save(list);
  return entry;
}
function all() { return load(); }
function clear() { save([]); }
function lastOfType(type) { return load().find((r) => r.type === type) || null; }

module.exports = { add, all, clear, lastOfType };
