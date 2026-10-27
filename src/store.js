import { DatabaseSync } from 'node:sqlite';

export function openStore(path = ':memory:') {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      report TEXT NOT NULL,
      events TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL REFERENCES reports(id),
      question TEXT NOT NULL,
      answer TEXT NOT NULL,
      refs TEXT NOT NULL,
      source TEXT NOT NULL
    );
  `);
  const insert = db.prepare('INSERT INTO reports (name, created_at, report, events) VALUES (?, ?, ?, ?)');
  const one = db.prepare('SELECT * FROM reports WHERE id = ?');
  const list = db.prepare('SELECT id, name, created_at FROM reports ORDER BY id DESC LIMIT 100');
  const addQ = db.prepare('INSERT INTO questions (report_id, question, answer, refs, source) VALUES (?, ?, ?, ?, ?)');
  const qs = db.prepare('SELECT question, answer, refs, source FROM questions WHERE report_id = ? ORDER BY id');

  return {
    save({ report, events }) {
      const r = insert.run(report.name, report.createdAt, JSON.stringify(report), JSON.stringify(events));
      return Number(r.lastInsertRowid);
    },
    get(id) {
      const row = one.get(id);
      if (!row) return null;
      return { id: row.id, report: JSON.parse(row.report), events: JSON.parse(row.events) };
    },
    list: () => list.all(),
    addQuestion(id, question, a) {
      addQ.run(id, question, a.answer, JSON.stringify(a.refs), a.source);
    },
    questions: (id) => qs.all(id).map((q) => ({ ...q, refs: JSON.parse(q.refs) })),
    close: () => db.close(),
  };
}
