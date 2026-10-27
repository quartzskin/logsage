const $ = (id) => document.getElementById(id);
let current = null;

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  Object.assign(n, props);
  for (const k of kids) n.append(k);
  return n;
}

async function api(path, body) {
  const res = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function render(id, report, questions = []) {
  current = id;
  $('report').hidden = false;
  $('meta').textContent = `${report.name} - ${report.format}, ${report.eventCount} events, ${report.mode === 'model' ? `model ${report.model}` : 'rules only'}`;
  $('export').href = `/api/reports/${id}/export`;

  const facts = $('facts');
  facts.replaceChildren();
  for (const g of report.facts.groups) {
    const box = el('div', { className: `group ${g.severity}` }, el('strong', { textContent: `${g.id} [${g.severity}] ${g.title}` }));
    for (const f of g.facts) box.append(el('div', { textContent: f }));
    for (const r of g.refs.slice(0, 25)) {
      box.append(el('pre', {}, el('span', { className: 'ref', textContent: `${r}  ` }), report.facts.evidence[r]));
    }
    facts.append(box);
  }
  facts.append(el('p', { textContent: `${report.facts.ungrouped} event(s) not in any group.` }));

  const interp = $('interp');
  interp.replaceChildren(el('p', { textContent: report.summary }));
  for (const i of report.interpretation) {
    interp.append(el('p', { textContent: `${i.group} (${i.confidence}): ${i.text} [${i.refs.join(', ')}]` }));
  }
  $('conf').textContent = `${report.confidence.level}. ${report.confidence.reason}`;
  $('unknowns').replaceChildren(...report.unknowns.map((u) => el('li', { textContent: u })));
  $('answers').replaceChildren(...questions.map(showAnswer));
}

function showAnswer(q) {
  return el('div', { className: 'group' },
    el('strong', { textContent: q.question }),
    el('pre', { textContent: q.answer }),
    el('div', { className: 'ref', textContent: `refs: ${q.refs.join(', ') || 'none'} (${q.source})` }));
}

async function loadReports() {
  const rows = await api('/api/reports');
  $('reports').replaceChildren(...rows.map((r) => {
    const a = el('a', { textContent: `#${r.id} ${r.name}` });
    a.onclick = async () => {
      const d = await api(`/api/reports/${r.id}`);
      render(d.id, d.report, d.questions);
    };
    return el('li', {}, a);
  }));
}

$('file').onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $('text').value = await f.text();
  $('name').value = f.name;
};

$('go').onclick = async () => {
  try {
    const d = await api('/api/analyze', { name: $('name').value, text: $('text').value, useModel: $('useModel').checked });
    render(d.id, d.report);
    loadReports();
  } catch (err) {
    alert(err.message);
  }
};

$('askForm').onsubmit = async (e) => {
  e.preventDefault();
  const question = $('q').value.trim();
  if (!question || current == null) return;
  try {
    const a = await api(`/api/reports/${current}/ask`, { question, useModel: $('useModel').checked });
    $('answers').append(showAnswer({ question, ...a }));
    $('q').value = '';
  } catch (err) {
    alert(err.message);
  }
};

api('/api/status').then((s) => {
  $('status').textContent = s.model ? `model ${s.model}: ${s.modelUp ? 'reachable' : 'not reachable, rules fallback'}` : 'no model configured';
});
loadReports();
