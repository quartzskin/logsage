import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLog } from '../src/parse.js';
import { redactEvents, createRedactor } from '../src/redact.js';

test('same value gets the same alias, case-insensitively', () => {
  const r = createRedactor();
  assert.equal(r.user('Alice'), r.user('alice'));
  assert.notEqual(r.user('alice'), r.user('bob'));
  assert.equal(r.user('SYSTEM'), 'SYSTEM');
});

test('redacted events carry no original users, ips or hosts', () => {
  const log = 'Mar 1 10:00:00 corpbox sshd[1]: Failed password for invalid user zoe from 198.51.100.7 port 22 ssh2 mail zoe@example.com\n';
  const { events } = redactEvents(parseLog(log).events);
  const dump = JSON.stringify(events);
  for (const s of ['zoe', '198.51.100.7', 'corpbox', 'example.com']) assert.ok(!dump.includes(s), s);
  assert.match(dump, /USER_1/);
  assert.match(dump, /IP_1/);
});

test('restore maps aliases back', () => {
  const { events, redactor } = redactEvents(parseLog('Mar 1 10:00:00 h sshd[1]: Failed password for bob from 10.1.1.1 port 1 ssh2\n').events);
  assert.equal(redactor.restore(`${events[0].user} at ${events[0].ip}`), 'bob at 10.1.1.1');
});

test('addresses and sids inside free text are masked', () => {
  const { events } = redactEvents(parseLog('{"Id":4625,"Message":"from 10.9.8.7 sid S-1-5-21-111-222-333-1001 fe80:0:0:0:1:2:3:4"}').events);
  assert.doesNotMatch(events[0].text, /10\.9\.8\.7|S-1-5-21|fe80/);
});
