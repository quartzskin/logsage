import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createServer } from '../src/server.js';
import { openStore } from '../src/store.js';

const sample = readFileSync(new URL('../samples/security.xml', import.meta.url), 'utf8');

function call(port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

async function withServer(fn) {
  const store = openStore();
  const server = createServer({ store });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    await fn(server.address().port, store);
  } finally {
    server.close();
    store.close();
  }
}

test('analyze, fetch, ask and export through the api', () => withServer(async (port) => {
  const a = await call(port, 'POST', '/api/analyze', { name: 'sec', text: sample });
  assert.equal(a.status, 200);
  const { id, report } = JSON.parse(a.text);
  assert.equal(report.mode, 'fallback');

  const q = await call(port, 'POST', `/api/reports/${id}/ask`, { question: 'which events came from 203.0.113.45?' });
  assert.ok(JSON.parse(q.text).refs.includes('X2'));

  const got = JSON.parse((await call(port, 'GET', `/api/reports/${id}`)).text);
  assert.equal(got.questions.length, 1);

  const md = await call(port, 'GET', `/api/reports/${id}/export`);
  assert.match(md.text, /## Follow-up questions/);
  assert.equal((await call(port, 'GET', '/api/reports/99')).status, 404);
}));

test('bad requests get 4xx, not a crash', () => withServer(async (port) => {
  assert.equal((await call(port, 'POST', '/api/analyze', { text: '' })).status, 400);
  const raw = await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/analyze' }, (res) => { res.resume(); resolve(res.statusCode); });
    req.end('{not json');
  });
  assert.equal(raw, 400);
  const junk = await call(port, 'POST', '/api/analyze', { text: '\u0000\u0001 <Event' });
  assert.equal(junk.status, 200);
}));

test('foreign host and origin headers are rejected', () => withServer(async (port) => {
  assert.equal((await call(port, 'GET', '/api/reports', undefined, { host: 'evil.example' })).status, 403);
  assert.equal((await call(port, 'POST', '/api/analyze', { text: 'x' }, { origin: 'http://evil.example' })).status, 403);
  assert.equal((await call(port, 'GET', '/')).status, 200);
}));
