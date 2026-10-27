const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

const WIN_KINDS = {
  4624: 'logon_success',
  4625: 'logon_failure',
  4672: 'privileged',
  4697: 'service_install',
  7045: 'service_install',
  4720: 'account_created',
  4728: 'group_change',
  4732: 'group_change',
  4756: 'group_change',
  1102: 'log_cleared',
};

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function unxml(s) {
  return s.replace(/&(lt|gt|amp|quot|apos);|&#(x?)([0-9a-f]+);/gi, (m, name, hex, num) => {
    if (name) return ENTITIES[name.toLowerCase()];
    const cp = parseInt(num, hex ? 16 : 10);
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
  });
}

function parseTime(s) {
  if (typeof s !== 'string') return null;
  const t = Date.parse(s.replace(/(\.\d{3})\d+/, '$1'));
  return Number.isNaN(t) ? null : t;
}

function psDate(v) {
  if (typeof v === 'number') return new Date(v).toISOString();
  if (typeof v !== 'string') return null;
  const m = /^\/?\\?\/?Date\((-?\d+)/.exec(v);
  return m ? new Date(Number(m[1])).toISOString() : v;
}

const dash = (v) => (v == null || v === '' || v === '-' ? null : String(v));

function messageData(msg) {
  const out = {};
  const accounts = [];
  for (const line of msg.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z][A-Za-z ]*?):\s+(.*?)\s*$/.exec(line);
    if (!m) continue;
    const [, key, val] = m;
    if (key === 'Account Name') accounts.push(val);
    else if (key === 'Source Network Address') out.IpAddress = val;
    else if (key === 'Logon Type') out.LogonType = val;
    else if (key === 'Workstation Name') out.WorkstationName = val;
    else if (key === 'Service Name') out.ServiceName = val;
    else if (key === 'Service File Name') out.ImagePath = val;
    else if (key === 'Service Account') out.AccountName = val;
    else if (key === 'Account Domain' || key === 'Target Domain') out.TargetDomainName = val;
  }
  if (accounts.length) {
    out.SubjectUserName = accounts[0];
    out.TargetUserName = [...accounts].reverse().find((a) => a !== '-') ?? '-';
  }
  return out;
}

function winEvent({ ref, id, time, provider, host, data, message }) {
  const d = { ...(message ? messageData(message) : {}), ...data };
  const kind = WIN_KINDS[id] ?? 'other';
  let user;
  if (id === 7045 || id === 4697) user = dash(d.AccountName) ?? dash(d.SubjectUserName);
  else if (kind === 'privileged' || kind === 'group_change' || kind === 'log_cleared') user = dash(d.SubjectUserName);
  else user = dash(d.TargetUserName) ?? dash(d.SubjectUserName);

  const ip = dash(d.IpAddress);
  const fields = {};
  if (d.LogonType) fields.logonType = String(d.LogonType);
  if (d.WorkstationName && dash(d.WorkstationName)) fields.workstation = d.WorkstationName;
  if (d.TargetDomainName && dash(d.TargetDomainName)) fields.domain = d.TargetDomainName;
  if (d.ServiceName) fields.serviceName = d.ServiceName;
  if (d.ImagePath) fields.serviceFile = d.ImagePath;
  if (kind === 'account_created' && dash(d.SubjectUserName)) fields.actor = d.SubjectUserName;
  if (kind === 'group_change' && dash(d.TargetUserName)) fields.group = d.TargetUserName;

  const text = message
    ? message.replace(/\s+/g, ' ').trim()
    : Object.entries(data).map(([k, v]) => `${k}=${v}`).join('; ');
  return {
    ref,
    source: 'windows',
    id,
    kind,
    time,
    ts: parseTime(time),
    host: dash(host),
    provider: provider ?? null,
    user,
    ip,
    text,
    fields,
  };
}

function parseXml(text) {
  const events = [];
  const warnings = [];
  const re = /<Event(?:\s[^>]*)?>[\s\S]*?<\/Event>/g;
  let n = 0;
  for (const m of text.matchAll(re)) {
    n++;
    const body = m[0];
    const ref = `X${n}`;
    const idm = /<EventID(?:\s[^>]*)?>\s*(\d+)\s*<\/EventID>/.exec(body);
    if (!idm) {
      warnings.push(`${ref}: no EventID, skipped`);
      continue;
    }
    const attr = (tag, name) => {
      const t = new RegExp(`<${tag}\\s[^>]*?${name}=(?:"([^"]*)"|'([^']*)')`).exec(body);
      return t ? unxml(t[1] ?? t[2]) : null;
    };
    const comp = /<Computer>([^<]*)<\/Computer>/.exec(body);
    const data = {};
    const dataRe = /<Data(?:\s+Name=(?:"([^"]*)"|'([^']*)'))?\s*(?:\/>|>([\s\S]*?)<\/Data>)/g;
    let i = 0;
    for (const dm of body.matchAll(dataRe)) {
      i++;
      data[unxml(dm[1] ?? dm[2] ?? `Data${i}`)] = unxml(dm[3] ?? '');
    }
    events.push(winEvent({
      ref,
      id: Number(idm[1]),
      time: attr('TimeCreated', 'SystemTime'),
      provider: attr('Provider', 'Name'),
      host: comp ? unxml(comp[1]) : null,
      data,
    }));
  }
  const opened = (text.match(/<Event[\s>]/g) || []).length;
  if (opened > n) warnings.push(`${opened - n} unterminated <Event> element(s) ignored`);
  return { events, warnings };
}

function parseJsonLines(text) {
  const events = [];
  const warnings = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    const ref = `L${i + 1}`;
    let o;
    try {
      o = JSON.parse(line);
    } catch {
      warnings.push(`${ref}: invalid JSON, skipped`);
      return;
    }
    const id = Number(o?.Id ?? o?.EventId);
    if (!o || typeof o !== 'object' || !Number.isInteger(id)) {
      warnings.push(`${ref}: no usable Id, skipped`);
      return;
    }
    events.push(winEvent({
      ref,
      id,
      time: psDate(o.TimeCreated),
      provider: o.ProviderName ?? null,
      host: o.MachineName,
      data: o.EventData && typeof o.EventData === 'object' ? o.EventData : {},
      message: typeof o.Message === 'string' ? o.Message : '',
    }));
  });
  return { events, warnings };
}

const SYSLOG = /^(?:(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)|(\d{4})-(\d\d)-(\d\d)T(\d\d:\d\d:\d\d)\S*)\s+(\S+)\s+([^\s:[]+)(?:\[\d+\])?:\s*(.*)$/;

function classifyAuth(proc, msg) {
  let m;
  if ((m = /^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port \d+/.exec(msg)))
    return { id: 'ssh-failed', kind: 'logon_failure', user: m[2], ip: m[3], fields: { method: m[1] } };
  if ((m = /^Accepted (\S+) for (\S+) from (\S+) port \d+/.exec(msg)))
    return { id: 'ssh-accepted', kind: 'logon_success', user: m[2], ip: m[3], fields: { method: m[1] } };
  if ((m = /^Invalid user (\S*) from (\S+)/.exec(msg)))
    return { id: 'ssh-invalid-user', kind: 'other', user: m[1] || null, ip: m[2], fields: {} };
  if (proc === 'sudo') {
    if ((m = /^\s*(\S+)\s*:.*\bCOMMAND=(.*)$/.exec(msg))) {
      const target = /\bUSER=(\S+)/.exec(msg);
      return { id: 'sudo', kind: 'privileged', user: m[1], ip: null, fields: { via: 'sudo', target: target?.[1] ?? '', command: m[2] } };
    }
    if ((m = /^\s*(\S+)\s*:\s*\d+ incorrect password attempts?/.exec(msg)))
      return { id: 'sudo-failed', kind: 'logon_failure', user: m[1], ip: null, fields: { via: 'sudo' } };
  }
  if ((m = /new user: name=([^,\s]+)/.exec(msg)))
    return { id: 'useradd', kind: 'account_created', user: m[1], ip: null, fields: {} };
  if ((m = /authentication failure;.*?(?:rhost=(\S*))?.*?\buser=(\S+)/.exec(msg)))
    return { id: 'pam-auth-failure', kind: 'other', user: m[2], ip: m[1] || null, fields: {} };
  return { id: proc, kind: 'other', user: null, ip: null, fields: {} };
}

function parseAuth(text, year) {
  const events = [];
  const warnings = [];
  let y = year;
  let prevMonth = null;
  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    const ref = `L${i + 1}`;
    const m = SYSLOG.exec(line);
    if (!m) {
      warnings.push(`${ref}: not a syslog line, skipped`);
      return;
    }
    let iso;
    if (m[1]) {
      const mon = MONTHS.indexOf(m[1]);
      if (mon < 0) {
        warnings.push(`${ref}: unknown month, skipped`);
        return;
      }
      if (prevMonth !== null && mon + 6 < prevMonth) y++;
      prevMonth = mon;
      iso = `${y}-${String(mon + 1).padStart(2, '0')}-${m[2].padStart(2, '0')}T${m[3]}`;
    } else {
      iso = `${m[4]}-${m[5]}-${m[6]}T${m[7]}`;
    }
    const ts = Date.parse(`${iso}Z`);
    const c = classifyAuth(m[9], m[10]);
    events.push({
      ref,
      source: 'auth',
      id: c.id,
      kind: c.kind,
      time: Number.isNaN(ts) ? null : iso.replace('T', ' '),
      ts: Number.isNaN(ts) ? null : ts,
      host: m[8],
      provider: m[9],
      user: c.user,
      ip: c.ip,
      text: m[10],
      fields: c.fields,
    });
  });
  return { events, warnings };
}

export function detectFormat(text) {
  const t = text.trimStart();
  if (t.startsWith('<')) return 'xml';
  if (t.startsWith('{')) return 'jsonl';
  return 'auth';
}

export function parseLog(input, { year = new Date().getFullYear(), format } = {}) {
  const text = String(input ?? '').replace(/^\uFEFF/, '');
  const fmt = format ?? detectFormat(text);
  const r = fmt === 'xml' ? parseXml(text) : fmt === 'jsonl' ? parseJsonLines(text) : parseAuth(text, year);
  if (!r.events.length && text.trim()) r.warnings.push(`no events recognised (treated as ${fmt})`);
  return { format: fmt, ...r };
}
