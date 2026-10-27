const KEEP = /^(-|system|local service|network service|anonymous logon|root|nt authority|window manager|dwm-\d+|umfd-\d+)$/i;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6 = /\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi;
const EMAIL = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g;
const SID = /\bS-1-\d+(?:-\d+){2,}\b/g;
const TOKEN = /\b(?:USER|IP|HOST|SID)_\d+\b/g;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function createRedactor() {
  const forward = new Map();
  const reverse = new Map();
  const counters = { USER: 0, IP: 0, HOST: 0, SID: 0 };
  const known = [];

  function alias(prefix, value) {
    const key = `${prefix}:${value.toLowerCase()}`;
    let tok = forward.get(key);
    if (!tok) {
      tok = `${prefix}_${++counters[prefix]}`;
      forward.set(key, tok);
      reverse.set(tok, value);
      known.push([value, tok]);
      known.sort((a, b) => b[0].length - a[0].length);
    }
    return tok;
  }

  const api = {
    user: (v) => (v == null || KEEP.test(v) ? v : alias('USER', v)),
    ip: (v) => (v == null ? v : alias('IP', v)),
    host: (v) => (v == null || KEEP.test(v) ? v : alias('HOST', v)),
    text(s) {
      let out = String(s);
      for (const [value, tok] of known) {
        out = out.replace(new RegExp(`(?<![\\w])${escapeRe(value)}(?![\\w])`, 'gi'), tok);
      }
      return out
        .replace(EMAIL, (m) => alias('USER', m))
        .replace(SID, (m) => alias('SID', m))
        .replace(IPV4, (m) => alias('IP', m))
        .replace(IPV6, (m) => alias('IP', m));
    },
    restore: (s) => String(s).replace(TOKEN, (t) => reverse.get(t) ?? t),
    mapping: () => Object.fromEntries(reverse),
  };
  return api;
}

export function redactEvents(events) {
  const r = createRedactor();
  for (const e of events) {
    r.user(e.user);
    r.ip(e.ip);
    r.host(e.host);
    r.user(e.fields.actor);
    r.host(e.fields.workstation);
    r.host(e.fields.domain);
  }
  const clean = events.map((e) => {
    const fields = {};
    for (const [k, v] of Object.entries(e.fields)) {
      fields[k] = k === 'actor' ? r.user(v) : k === 'workstation' || k === 'domain' ? r.host(v) : r.text(v);
    }
    return {
      ...e,
      user: r.user(e.user),
      ip: r.ip(e.ip),
      host: r.host(e.host),
      text: r.text(e.text).slice(0, 300),
      fields,
    };
  });
  return { events: clean, redactor: r };
}
