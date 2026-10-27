import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { analyze, ask } from './analyze.js';
import { toMarkdown } from './export.js';

const PUBLIC = fileURLToPath(new URL('../public/', import.meta.url));
const STATIC = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'] };
const MAX_BODY = 20 * 1024 * 1024;
const LOCAL = /^(127\.0\.0\.1|localhost)(:\d+)?$/;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('body too large'), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function createServer({ store, client = null }) {
  const send = (res, status, body, type = 'application/json') => {
    res.writeHead(status, { 'content-type': `${type}; charset=utf-8`, 'cache-control': 'no-store' });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  return http.createServer(async (req, res) => {
    try {
      // Blocks DNS-rebinding and cross-site requests to the local API.
      if (!LOCAL.test(req.headers.host ?? '')) return send(res, 403, { error: 'bad host' });
      const origin = req.headers.origin;
      if (origin && !LOCAL.test(new URL(origin).host)) return send(res, 403, { error: 'bad origin' });

      const url = new URL(req.url, 'http://localhost');
      const path = url.pathname;

      if (req.method === 'GET' && STATIC[path]) {
        const [file, type] = STATIC[path];
        return send(res, 200, await readFile(PUBLIC + file), type);
      }
      if (req.method === 'GET' && path === '/api/status') {
        return send(res, 200, { model: client ? client.model : null, modelUp: client ? await client.available() : false });
      }
      if (req.method === 'GET' && path === '/api/reports') return send(res, 200, store.list());

      if (req.method === 'POST' && path === '/api/analyze') {
        const body = JSON.parse(await readBody(req));
        if (typeof body.text !== 'string' || !body.text.trim()) return send(res, 400, { error: 'text is required' });
        const useModel = body.useModel !== false && client;
        const result = await analyze({ name: String(body.name || 'pasted log').slice(0, 120), text: body.text, client: useModel ? client : null });
        return send(res, 200, { id: store.save(result), report: result.report });
      }

      const m = /^\/api\/reports\/(\d+)(\/(ask|export))?$/.exec(path);
      if (m) {
        const stored = store.get(Number(m[1]));
        if (!stored) return send(res, 404, { error: 'no such report' });
        if (req.method === 'GET' && !m[3]) {
          return send(res, 200, { id: stored.id, report: stored.report, questions: store.questions(stored.id) });
        }
        if (req.method === 'GET' && m[3] === 'export') {
          return send(res, 200, toMarkdown(stored.report, store.questions(stored.id)), 'text/markdown');
        }
        if (req.method === 'POST' && m[3] === 'ask') {
          const { question, useModel } = JSON.parse(await readBody(req));
          if (typeof question !== 'string' || !question.trim()) return send(res, 400, { error: 'question is required' });
          const q = question.slice(0, 500);
          const a = await ask(stored.report, stored.events, q, useModel !== false ? client : null);
          store.addQuestion(stored.id, q, a);
          return send(res, 200, a);
        }
      }
      send(res, 404, { error: 'not found' });
    } catch (err) {
      const status = err.status ?? (err instanceof SyntaxError ? 400 : 500);
      send(res, status, { error: status === 500 ? 'internal error' : err.message });
    }
  });
}
