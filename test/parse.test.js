import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseLog } from '../src/parse.js';
import { groupEvents } from '../src/group.js';

const sample = (n) => readFileSync(new URL(`../samples/${n}`, import.meta.url), 'utf8');

test('parses wevtutil xml', () => {
  const r = parseLog(sample('security.xml'));
  assert.equal(r.format, 'xml');
  assert.equal(r.events.length, 11);
  const f = r.events.find((e) => e.id === 4625);
  assert.equal(f.user, 'administrator');
  assert.equal(f.ip, '203.0.113.45');
  assert.equal(f.ref, 'X2');
});

test('parses Get-WinEvent json lines and skips bad lines', () => {
  const r = parseLog(sample('getwinevent.jsonl'));
  assert.equal(r.format, 'jsonl');
  assert.equal(r.events.length, 6);
  assert.deepEqual(r.warnings, ['L5: invalid JSON, skipped']);
  const ok = r.events.find((e) => e.id === 4624);
  assert.equal(ok.user, 'backup');
  assert.equal(ok.ip, '198.51.100.9');
  assert.equal(ok.time, '2024-05-02T22:10:13.000Z');
});

test('parses auth.log with line refs', () => {
  const r = parseLog(sample('auth.log'), { year: 2024 });
  assert.equal(r.events.length, 10);
  assert.equal(r.events[0].ref, 'L1');
  assert.equal(r.events[0].user, 'oracle');
  assert.equal(r.events[6].kind, 'privileged');
  assert.deepEqual(r.warnings, ['L11: not a syslog line, skipped']);
});

test('xml entities are decoded', () => {
  const xml = '<Event><System><EventID>4625</EventID><Computer>h</Computer></System><EventData><Data Name="TargetUserName">a&amp;b&lt;c</Data></EventData></Event>';
  assert.equal(parseLog(xml).events[0].user, 'a&b<c');
});

test('malformed input does not throw', () => {
  const inputs = ['', '   ', '<Event><System><EventID>abc</EventID></System></Event>', '<Event><System><EventID>4625</EventID>', '{"Id": "x"}\n[1,2]\nnull', '\0\0\0', 'Feb 31 99:99:99 h p: x', '<<<>>>'];
  for (const i of inputs) {
    const r = parseLog(i);
    assert.ok(Array.isArray(r.events));
    assert.ok(Array.isArray(r.warnings));
  }
  assert.equal(parseLog('<Event><System><EventID>4625</EventID>').warnings.length > 0, true);
  assert.equal(parseLog('{"Id": 4625}').events.length, 1);
});

test('groups failures then success then privileges', () => {
  const { groups } = groupEvents(parseLog(sample('security.xml')).events);
  const g = groups.find((x) => x.type === 'failures_then_success');
  assert.equal(g.severity, 'high');
  assert.deepEqual(g.refs, ['X2', 'X3', 'X4', 'X5', 'X6', 'X7', 'X8']);
  assert.ok(groups.some((x) => x.type === 'service_install' && x.severity === 'high'));
  assert.equal(groups.find((x) => x.type === 'privileged_logon').severity, 'info');
});

test('two failures are not a group', () => {
  const log = 'Mar 1 10:00:00 h sshd[1]: Failed password for bob from 1.2.3.4 port 1 ssh2\nMar 1 10:00:01 h sshd[1]: Failed password for bob from 1.2.3.4 port 1 ssh2\n';
  assert.equal(groupEvents(parseLog(log).events).groups.length, 0);
});

test('failures far apart in time are split', () => {
  const l = (m) => `Mar 1 10:${m}:00 h sshd[1]: Failed password for bob from 1.2.3.4 port 1 ssh2`;
  const log = [l('00'), l('01'), l('50'), l('51')].join('\n');
  assert.equal(groupEvents(parseLog(log).events).groups.length, 0);
});
