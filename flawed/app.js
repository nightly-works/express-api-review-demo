import express from 'express';
import bcrypt from 'bcryptjs';
import { signToken, requireAuth } from './auth.js';

export function createApp(db) {
  const app = express();
  app.use(express.json());

  app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    res.json({ token: signToken(user) });
  });

  app.post('/api/password/forgot', (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email);
    if (user) {
      const token = Math.random().toString(36).slice(2);
      db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(token, user.id);
      // sendResetEmail(user.email, token)
    }
    res.json({ ok: true });
  });

  app.post('/api/password/reset', (req, res) => {
    const { token, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(token);
    if (!user) return res.status(400).json({ error: 'Invalid token' });
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), user.id);
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, (req, res) => {
    res.json(db.prepare('SELECT id, email, name, role, workspace_id FROM users WHERE id = ?').get(req.user.id));
  });

  app.patch('/api/me', requireAuth, (req, res) => {
    const fields = Object.keys(req.body);
    if (fields.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    const sets = fields.map((f) => `${f} = ?`).join(', ');
    db.prepare(`UPDATE users SET ${sets} WHERE id = ?`).run(...Object.values(req.body), req.user.id);
    res.json(db.prepare('SELECT id, email, name, role, workspace_id FROM users WHERE id = ?').get(req.user.id));
  });

  app.get('/api/team', requireAuth, (req, res) => {
    res.json(db.prepare('SELECT * FROM users WHERE workspace_id = ?').all(req.user.workspace_id));
  });

  app.get('/api/documents', requireAuth, (req, res) => {
    res.json(db.prepare('SELECT id, title FROM documents WHERE workspace_id = ?').all(req.user.workspace_id));
  });

  app.get('/api/documents/:id', requireAuth, (req, res) => {
    const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  });

  app.delete('/api/documents/:id', requireAuth, (req, res) => {
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.params.id);
    res.status(204).end();
  });

  return app;
}
