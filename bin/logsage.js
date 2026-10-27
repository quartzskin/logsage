#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { analyze } from '../src/analyze.js';
import { OllamaClient } from '../src/model.js';
import { openStore } from '../src/store.js';
import { createServer } from '../src/server.js';
import { toMarkdown } from '../src/export.js';

const USAGE = `usage:
  logsage serve [--port 8787] [--db logsage.db] [--model NAME] [--ollama URL]
  logsage report FILE [--out report.md] [--model NAME] [--ollama URL]

Without --model nothing is sent anywhere and the rule-based reading is used.
Environment: LOGSAGE_MODEL, LOGSAGE_OLLAMA_URL.`;

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    port: { type: 'string', default: '8787' },
    db: { type: 'string', default: 'logsage.db' },
    model: { type: 'string', default: process.env.LOGSAGE_MODEL },
    ollama: { type: 'string', default: process.env.LOGSAGE_OLLAMA_URL },
    out: { type: 'string' },
    year: { type: 'string' },
  },
});

const [cmd, file] = positionals;
const client = values.model ? new OllamaClient({ model: values.model, baseUrl: values.ollama }) : null;

if (cmd === 'serve') {
  const server = createServer({ store: openStore(values.db), client });
  server.listen(Number(values.port), '127.0.0.1', () => {
    console.log(`logsage on http://127.0.0.1:${values.port}/ (${client ? `model ${client.model}` : 'no model'})`);
  });
} else if (cmd === 'report' && file) {
  const text = readFileSync(file, 'utf8');
  const { report } = await analyze({ name: file, text, client, year: values.year ? Number(values.year) : undefined });
  const md = toMarkdown(report);
  if (values.out) writeFileSync(values.out, md);
  else process.stdout.write(md);
} else {
  console.error(USAGE);
  process.exit(2);
}
