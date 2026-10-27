const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function toMarkdown(report, questions = []) {
  const out = [];
  out.push(`# Log report: ${report.name}`, '');
  out.push(`Generated ${report.createdAt}. Format: ${report.format}. Events parsed: ${report.eventCount}. Interpretation by: ${report.mode === 'model' ? `model (${report.model})` : 'built-in rules, no model'}.`, '');

  out.push('## Raw facts', '');
  const { groups, evidence, ungrouped } = report.facts;
  if (!groups.length) out.push('No grouped activity found.', '');
  for (const g of groups) {
    out.push(`### ${g.id} [${g.severity}] ${g.title}`, '');
    for (const f of g.facts) out.push(`- ${f}`);
    out.push('', `Evidence refs: ${g.refs.join(', ')}`, '');
    out.push('| ref | event |', '| --- | --- |');
    for (const r of g.refs.slice(0, 25)) out.push(`| ${r} | ${cell(evidence[r])} |`);
    if (g.refs.length > 25) out.push(`| | ${g.refs.length - 25} more not shown |`);
    out.push('');
  }
  out.push(`${ungrouped} parsed event(s) did not fall into any group.`, '');

  out.push('## Interpretation', '', report.summary, '');
  for (const i of report.interpretation) {
    out.push(`- ${i.group} (confidence ${i.confidence}): ${i.text} [${i.refs.join(', ')}]`);
  }
  out.push('', '## Confidence', '', `${report.confidence.level}. ${report.confidence.reason}`, '');

  out.push('## Unknowns', '');
  for (const u of report.unknowns) out.push(`- ${u}`);
  out.push('');

  if (report.warnings.length) {
    out.push('## Parse warnings', '');
    for (const w of report.warnings) out.push(`- ${w}`);
    out.push('');
  }
  if (questions.length) {
    out.push('## Follow-up questions', '');
    for (const q of questions) out.push(`**Q:** ${q.question}`, '', `${q.answer.replace(/\n/g, '\n> ')}`, '', `Refs: ${q.refs.join(', ') || 'none'} (${q.source})`, '');
  }
  return out.join('\n');
}
