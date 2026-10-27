import { parseLog } from './parse.js';
import { groupEvents } from './group.js';
import { redactEvents } from './redact.js';
import { analysisMessages, questionMessages, parseModelJson, validateAnalysis, validateAnswer } from './model.js';

const STOP = new Set(['the', 'a', 'an', 'is', 'was', 'were', 'did', 'do', 'does', 'what', 'who', 'when', 'where', 'why', 'how', 'and', 'or', 'of', 'to', 'in', 'on', 'for', 'from', 'by', 'with', 'any', 'there', 'this', 'that', 'it', 'me', 'show', 'tell']);
const KIND_WORDS = [
  [/fail|wrong|denied|brute|guess/, 'logon_failure'],
  [/success|accept|logged in|login|logon/, 'logon_success'],
  [/privileg|sudo|admin|elevat|root/, 'privileged'],
  [/service|install/, 'service_install'],
  [/account|created|useradd/, 'account_created'],
  [/group|member/, 'group_change'],
  [/clear|wipe/, 'log_cleared'],
];

const FALLBACK_TEXT = {
  repeated_failures: 'A burst of failed logons with no success afterwards in this log. This fits password guessing or a misconfigured client; the log cannot say which.',
  failures_then_success: 'Failed logons were followed by a success from the same source or for the same account. This is the shape of a guessed or reused credential, but it is also what a user who mistyped a password looks like.',
  privileged_logon: 'An account was given special privileges at logon. Expected for administrators and service accounts; worth a look if the account is not normally an admin.',
  sudo_use: 'Commands were run with elevated rights through sudo. Check them against what the user is expected to do.',
  service_install: 'A new service was registered. Persistence often looks like this; installers and drivers also do it legitimately.',
  account_created: 'A new local account was created. Confirm it was a planned change.',
  group_change: 'A security group membership was modified. Confirm it was a planned change.',
  log_cleared: 'The audit log was cleared. This removes evidence and is rarely routine.',
};

const CONFIDENCE = {
  repeated_failures: 'medium',
  failures_then_success: 'medium',
  privileged_logon: 'low',
  sudo_use: 'low',
  service_install: 'medium',
  account_created: 'low',
  group_change: 'low',
  log_cleared: 'medium',
};

export function evidenceLine(e) {
  const bits = [e.time ?? 'no time', e.source === 'windows' ? `event ${e.id}` : e.id];
  if (e.user) bits.push(`user=${e.user}`);
  if (e.ip) bits.push(`ip=${e.ip}`);
  if (e.host) bits.push(`host=${e.host}`);
  return `${bits.join(' ')} | ${e.text.slice(0, 200)}`;
}

function unknownsFor(parsed, groups) {
  const u = [];
  const { events, warnings } = parsed;
  if (warnings.length) u.push(`${warnings.length} input line(s) or record(s) could not be parsed and are not part of this analysis.`);
  const noTime = events.filter((e) => e.ts == null).length;
  if (noTime) u.push(`${noTime} event(s) have no usable timestamp, so ordering and time windows for them are uncertain.`);
  const noIp = events.filter((e) => e.kind === 'logon_failure' && !e.ip).length;
  if (noIp) u.push(`${noIp} failed logon(s) carry no source address.`);
  if (groups.some((g) => g.type === 'failures_then_success')) {
    u.push('The log cannot show whether the successful logon was the same person as the failed attempts.');
  }
  if (!events.length) u.push('No events were recognised, so nothing can be said about this input.');
  u.push('Only this one file was examined; activity before or after it, or on other machines, is not visible.');
  return u;
}

function fallbackAnalysis(groups) {
  const interpretations = groups
    .filter((g) => g.severity !== 'info')
    .map((g) => ({ group: g.id, text: FALLBACK_TEXT[g.type], refs: g.refs, confidence: CONFIDENCE[g.type] }));
  const notable = groups.filter((g) => g.severity === 'high' || g.severity === 'medium');
  return {
    summary: groups.length
      ? `${groups.length} group(s) found, ${notable.length} of medium or high severity.`
      : 'No grouped activity found by the built-in rules.',
    interpretations,
    confidence: {
      level: notable.length ? 'medium' : 'low',
      reason: 'Rule-based reading of event patterns only; no model was used and intent cannot be judged from logs alone.',
    },
    unknowns: [],
  };
}

export async function analyze({ name = 'input', text, year, client = null }) {
  const parsed = parseLog(text, { year });
  const { groups, ungrouped } = groupEvents(parsed.events);
  const { events: clean, redactor } = redactEvents(parsed.events);
  const cleanGroups = groupEvents(clean).groups;
  const warnings = parsed.warnings.slice(0, 20);
  if (parsed.warnings.length > 20) warnings.push(`...and ${parsed.warnings.length - 20} more`);

  let analysis = null;
  let mode = 'fallback';
  let modelNote = null;
  if (client && groups.length) {
    try {
      const reply = await client.chat(analysisMessages(cleanGroups, clean));
      const checked = validateAnalysis(parseModelJson(reply), groups);
      if (checked.interpretations.length) {
        analysis = checked;
        mode = 'model';
      } else {
        modelNote = 'The model reply had no claims backed by valid evidence references; using the rule-based reading instead.';
      }
    } catch (err) {
      modelNote = `Model call failed (${err.message}); using the rule-based reading instead.`;
    }
  }
  if (!analysis) analysis = fallbackAnalysis(groups);
  else {
    analysis.summary = redactor.restore(analysis.summary);
    for (const i of analysis.interpretations) i.text = redactor.restore(i.text);
    analysis.unknowns = analysis.unknowns.map((s) => redactor.restore(s));
    if (analysis.confidence) analysis.confidence.reason = redactor.restore(analysis.confidence.reason);
    analysis.confidence ??= { level: 'low', reason: 'The model gave no overall confidence.' };
  }

  const unknowns = [...analysis.unknowns, ...unknownsFor(parsed, groups)];
  if (analysis.dropped) unknowns.push(`${analysis.dropped} model claim(s) were dropped because they cited no valid evidence.`);
  if (modelNote) unknowns.push(modelNote);

  const byRef = new Map(parsed.events.map((e) => [e.ref, e]));
  const evidence = {};
  for (const r of groups.flatMap((g) => g.refs)) evidence[r] = evidenceLine(byRef.get(r));

  const report = {
    name,
    createdAt: new Date().toISOString(),
    format: parsed.format,
    mode,
    model: mode === 'model' ? client.model : null,
    eventCount: parsed.events.length,
    warnings,
    facts: { groups, ungrouped, evidence },
    summary: analysis.summary,
    interpretation: analysis.interpretations,
    confidence: analysis.confidence,
    unknowns,
  };
  return { report, events: parsed.events };
}

function tokens(q) {
  return q.toLowerCase().match(/[\w.:@\\-]+/g)?.filter((t) => !STOP.has(t) && t.length > 1) ?? [];
}

export function selectEvidence(report, events, question, limit = 20) {
  const toks = tokens(question);
  const kinds = new Set(KIND_WORDS.filter(([re]) => re.test(question.toLowerCase())).map(([, k]) => k));
  const fromGroups = new Set();
  for (const t of toks) {
    const g = report.facts.groups.find((x) => x.id.toLowerCase() === t);
    if (g) g.refs.forEach((r) => fromGroups.add(r));
  }
  const scored = [];
  for (const e of events) {
    const hay = [e.ref, e.id, e.user, e.ip, e.host, e.provider, e.text, ...Object.values(e.fields)]
      .filter((v) => v != null).join(' ').toLowerCase();
    let score = fromGroups.has(e.ref) ? 3 : 0;
    for (const t of toks) if (hay.includes(t)) score += e.ref.toLowerCase() === t ? 3 : 1;
    if (kinds.has(e.kind)) score += 1;
    if (score > 0) scored.push([score, e]);
  }
  return scored.sort((a, b) => b[0] - a[0]).slice(0, limit).map(([, e]) => e);
}

export async function ask(report, events, question, client = null) {
  const picked = selectEvidence(report, events, question);
  if (!picked.length) {
    return { answer: 'Nothing in the stored evidence matches that question.', refs: [], source: 'none' };
  }
  const refs = picked.map((e) => e.ref);
  const list = () => ({
    answer: `Matching evidence (${picked.length}):\n${picked.map((e) => `${e.ref}: ${evidenceLine(e)}`).join('\n')}`,
    refs,
    source: 'evidence',
  });
  if (!client) return list();
  const { events: clean, redactor } = redactEvents(events);
  const cleanPicked = clean.filter((e) => refs.includes(e.ref));
  try {
    const reply = await client.chat(questionMessages(redactor.text(question), cleanPicked));
    const ok = validateAnswer(parseModelJson(reply), new Set(refs));
    if (!ok) return { ...list(), answer: `The model could not answer from this evidence.\n${list().answer}` };
    return { answer: redactor.restore(ok.answer), refs: ok.refs, source: 'model' };
  } catch (err) {
    return { ...list(), answer: `Model call failed (${err.message}).\n${list().answer}` };
  }
}
