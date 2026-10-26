import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';

export function openDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE workspaces (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      password_hash TEXT NOT NULL,
      reset_token_hash TEXT,
      reset_expires_at INTEGER,
      token_version INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE documents (
      id INTEGER PRIMARY KEY,
      workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
      title TEXT NOT NULL,
      body TEXT NOT NULL
    );
  `);
  return db;
}

// Two client companies on the same instance, as in production.
// rounds = 4 keeps the tests fast; production hashes use 10 or more.
export function seed(db, { rounds = 4 } = {}) {
  const hash = (p) => bcrypt.hashSync(p, rounds);
  db.exec(`INSERT INTO workspaces (id, name) VALUES (1, 'Acme'), (2, 'Globex')`);
  const user = db.prepare(
    'INSERT INTO users (id, workspace_id, email, name, role, password_hash) VALUES (?, ?, ?, ?, ?, ?)'
  );
  user.run(1, 1, 'alice@acme.test', 'Alice', 'owner', hash('alice-password-1'));
  user.run(2, 1, 'bob@acme.test', 'Bob', 'member', hash('bob-password-1'));
  user.run(3, 2, 'carol@globex.test', 'Carol', 'owner', hash('carol-password-1'));
  const doc = db.prepare('INSERT INTO documents (id, workspace_id, title, body) VALUES (?, ?, ?, ?)');
  doc.run(1, 1, 'Acme pricing 2027', 'Enterprise tier at 1,200 EUR a month.');
  doc.run(2, 2, 'Globex acquisition memo', 'Board approved the offer on 12 October.');
}
