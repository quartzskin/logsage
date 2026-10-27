const WINDOW_MS = 10 * 60 * 1000;
const PRIV_FOLLOW_MS = 60 * 1000;
const MIN_FAILURES = 3;
const SEVERITY = { high: 0, medium: 1, low: 2, info: 3 };
const BUILTIN = /^(system|local service|network service|anonymous logon|root|dwm-\d+|umfd-\d+)$/i;
const SUSPECT_PATH = /\\(?:temp|appdata|users\\public|programdata)\\|powershell|cmd(?:\.exe)?\s+\/c|\s-enc/i;

const uniq = (a) => [...new Set(a.filter(Boolean))];
const span = (evs) => {
  const t = evs.map((e) => e.time).filter(Boolean);
  return t.length ? `${t[0]} to ${t[t.length - 1]}` : 'time unknown';
};
const label = (e) => (e.source === 'windows' ? `event ${e.id}` : e.id);

function make(type, severity, title, evs, facts) {
  return { type, severity, title, refs: evs.map((e) => e.ref), count: evs.length, first: evs[0].time, last: evs[evs.length - 1].time, facts };
}

function failureGroups(sorted) {
  const idx = new Map(sorted.map((e, i) => [e, i]));
  const out = [];
  const used = new Set();
  const byKey = new Map();
  for (const e of sorted) {
    if (e.kind !== 'logon_failure') continue;
    const key = e.ip ?? (e.user ? `user:${e.user.toLowerCase()}` : 'unknown');
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(e);
  }
  for (const [key, list] of byKey) {
    const clusters = [];
    for (const e of list) {
      const cur = clusters[clusters.length - 1];
      const prev = cur?.[cur.length - 1];
      if (prev && (e.ts == null || prev.ts == null || e.ts - prev.ts <= WINDOW_MS)) cur.push(e);
      else clusters.push([e]);
    }
    for (const c of clusters) {
      if (c.length < MIN_FAILURES) continue;
      const users = uniq(c.map((e) => e.user));
      const ip = c[0].ip;
      const where = ip ? `from ${ip}` : key.startsWith('user:') ? `against ${c[0].user}` : 'with no source address';
      const facts = [
        `${c.length} failed logons (${uniq(c.map(label)).join(', ')}) ${where}, ${span(c)}`,
        `accounts tried: ${users.join(', ') || 'none recorded'}`,
      ];
      const last = c[c.length - 1];
      const next = sorted.find((s) => s.kind === 'logon_success'
        && idx.get(s) > idx.get(last)
        && (last.ts == null || s.ts == null || s.ts - last.ts <= WINDOW_MS)
        && ((ip && s.ip === ip) || (s.user && users.some((u) => u.toLowerCase() === s.user.toLowerCase()))));
      if (!next) {
        for (const e of c) used.add(e.ref);
        out.push(make('repeated_failures', 'medium', `Repeated failed logons ${where}`, c, facts));
        continue;
      }
      const evs = [...c, next];
      facts.push(`then a successful logon (${label(next)}) for ${next.user ?? 'unknown account'}${next.ip ? ` from ${next.ip}` : ''} at ${next.time ?? 'unknown time'}`);
      const priv = sorted.find((s) => s.kind === 'privileged' && !s.fields.via && s.user && s.user === next.user
        && idx.get(s) > idx.get(next) && (next.ts == null || s.ts == null || s.ts - next.ts <= PRIV_FOLLOW_MS));
      if (priv) {
        evs.push(priv);
        facts.push(`the same account was assigned special privileges (event ${priv.id}) shortly after`);
      }
      for (const e of evs) used.add(e.ref);
      out.push(make('failures_then_success', 'high', `Failed logons ${where} followed by a success`, evs, facts));
    }
  }
  return { groups: out, used };
}

export function groupEvents(events) {
  const sorted = [...events].sort((a, b) => (a.ts ?? Infinity) - (b.ts ?? Infinity));
  const { groups, used } = failureGroups(sorted);

  const privByUser = new Map();
  for (const e of sorted) {
    if (e.kind !== 'privileged' || used.has(e.ref)) continue;
    const key = `${e.fields.via ?? 'win'}:${(e.user ?? '').toLowerCase()}`;
    if (!privByUser.has(key)) privByUser.set(key, []);
    privByUser.get(key).push(e);
  }
  for (const list of privByUser.values()) {
    const user = list[0].user ?? 'unknown account';
    if (list[0].fields.via === 'sudo') {
      const cmds = uniq(list.map((e) => `${e.fields.target || '?'}: ${e.fields.command}`)).slice(0, 5);
      groups.push(make('sudo_use', BUILTIN.test(user) ? 'info' : 'low', `sudo use by ${user}`, list,
        [`${list.length} sudo command(s) by ${user}, ${span(list)}`, `commands: ${cmds.join(' | ')}`]));
    } else {
      const builtin = BUILTIN.test(user);
      groups.push(make('privileged_logon', builtin ? 'info' : 'low', `Special privileges assigned to ${user}`, list,
        [`${list.length} logon(s) with special privileges (event 4672) for ${user}, ${span(list)}`]));
    }
  }

  for (const e of sorted) {
    if (e.kind === 'service_install') {
      const file = e.fields.serviceFile ?? '';
      const odd = SUSPECT_PATH.test(file);
      groups.push(make('service_install', odd ? 'high' : 'medium', `Service installed: ${e.fields.serviceName ?? 'unnamed'}`, [e],
        [`${label(e)}: service "${e.fields.serviceName ?? 'unnamed'}" installed at ${e.time ?? 'unknown time'}`,
          `binary path: ${file || 'not recorded'}${odd ? ' (path or command looks unusual for a service)' : ''}`]));
    } else if (e.kind === 'account_created') {
      groups.push(make('account_created', 'medium', `Account created: ${e.user}`, [e],
        [`${label(e)}: account ${e.user} created${e.fields.actor ? ` by ${e.fields.actor}` : ''} at ${e.time ?? 'unknown time'}`]));
    } else if (e.kind === 'group_change') {
      groups.push(make('group_change', 'medium', 'Group membership changed', [e],
        [`${label(e)}: membership change${e.fields.group ? ` on ${e.fields.group}` : ''} by ${e.user ?? 'unknown'} at ${e.time ?? 'unknown time'}`]));
    } else if (e.kind === 'log_cleared') {
      groups.push(make('log_cleared', 'high', 'Event log cleared', [e],
        [`${label(e)}: audit log cleared by ${e.user ?? 'unknown'} at ${e.time ?? 'unknown time'}`]));
    }
  }

  const rank = (g) => SEVERITY[g.severity];
  const order = new Map(sorted.map((e, i) => [e.ref, i]));
  groups.sort((a, b) => rank(a) - rank(b) || order.get(a.refs[0]) - order.get(b.refs[0]));
  groups.forEach((g, i) => { g.id = `G${i + 1}`; });

  const grouped = new Set(groups.flatMap((g) => g.refs));
  return { groups, ungrouped: events.filter((e) => !grouped.has(e.ref)).length };
}
