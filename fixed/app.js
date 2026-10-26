import express from 'express';
import bcrypt from 'bcryptjs';
import { createHash, randomBytes } from 'node:crypto';
import { createAuth } from './auth.js';

const RESET_TTL_MS = 30 * 60 * 1000;
const PUBLIC_USER = 'id, email, name, role, workspace_id';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
// bcrypt reads only the first 72 bytes of a password; longer ones are refused, not cut.
const passwordOk = (p) => typeof p === 'string' && p.length >= 10 && Buffer.byteLength(p) <= 72;
// Compared against when the email is unknown, so a login takes as long either way.
const DUMMY_HASH = bcrypt.hashSync('no-such-user-password', 12);

export function createApp(db, { jwtSecret, now = Date.now } = {}) {
  const { signToken, requireAuth } = createAuth(db, jwtSecret);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));

  app.post('/api/login', async (req, res) => {
    const { email, password } = req.body ?? {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const matches = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !matches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    res.json({ token: signToken(user) });
  });

  // The emailed token is 32 random bytes; only its hash is stored, it expires after
  // 30 minutes and works once.
  app.post('/api/password/forgot', (req, res) => {
    const email = req.body?.email;
    const user = typeof email === 'string' ? db.prepare('SELECT id FROM users WHERE email = ?').get(email) : undefined;
    if (user) {
      const token = randomBytes(32).toString('base64url');
      db.prepare('UPDATE users SET reset_token_hash = ?, reset_expires_at = ? WHERE id = ?').run(
        sha256(token),
        now() + RESET_TTL_MS,
        user.id
      );
      app.locals.sendResetEmail?.(email, token);
    }
    res.json({ ok: true });
  });

  app.post('/api/password/reset', async (req, res) => {
    const { token, password } = req.body ?? {};
    if (typeof token !== 'string' || !passwordOk(password)) {
      return res.status(400).json({ error: 'Invalid token, or password not 10 to 72 bytes' });
    }
    const tokenHash = sha256(token);
    const user = db.prepare('SELECT id, reset_expires_at FROM users WHERE reset_token_hash = ?').get(tokenHash);
    if (!user || user.reset_expires_at < now()) return res.status(400).json({ error: 'Invalid token' });
    const passwordHash = await bcrypt.hash(password, 12);
    // The token is matched again in the update, so two requests racing with it change the
    // password once. Bumping the version ends every session opened before the reset.
    const result = db
      .prepare(
        `UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_expires_at = NULL,
           token_version = token_version + 1 WHERE id = ? AND reset_token_hash = ?`
      )
      .run(passwordHash, user.id, tokenHash);
    if (result.changes !== 1) return res.status(400).json({ error: 'Invalid token' });
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, (req, res) => {
    res.json(db.prepare(`SELECT ${PUBLIC_USER} FROM users WHERE id = ?`).get(req.user.id));
  });

  // Only the display name is editable here. Role and workspace change through the
  // owner's team screen; email changes need a confirmation flow of their own.
  app.patch('/api/me', requireAuth, (req, res) => {
    const body = req.body ?? {};
    const unknown = Object.keys(body).filter((key) => key !== 'name');
    if (unknown.length > 0) return res.status(400).json({ error: `Not editable: ${unknown.join(', ')}` });
    if (typeof body.name !== 'string' || body.name.trim() === '' || body.name.length > 100) {
      return res.status(400).json({ error: 'Name must be 1 to 100 characters' });
    }
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(body.name.trim(), req.user.id);
    res.json(db.prepare(`SELECT ${PUBLIC_USER} FROM users WHERE id = ?`).get(req.user.id));
  });

  app.get('/api/team', requireAuth, (req, res) => {
    res.json(db.prepare(`SELECT ${PUBLIC_USER} FROM users WHERE workspace_id = ?`).all(req.user.workspace_id));
  });

  app.get('/api/documents', requireAuth, (req, res) => {
    res.json(db.prepare('SELECT id, title FROM documents WHERE workspace_id = ?').all(req.user.workspace_id));
  });

  // A document outside the caller's workspace answers 404, the same as a missing one,
  // so ids from other companies cannot be probed.
  app.get('/api/documents/:id', requireAuth, (req, res) => {
    const doc = db
      .prepare('SELECT id, title, body FROM documents WHERE id = ? AND workspace_id = ?')
      .get(req.params.id, req.user.workspace_id);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  });

  app.delete('/api/documents/:id', requireAuth, (req, res) => {
    const result = db
      .prepare('DELETE FROM documents WHERE id = ? AND workspace_id = ?')
      .run(req.params.id, req.user.workspace_id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.status(204).end();
  });

  // Malformed JSON and unexpected errors answer in JSON, without a stack trace.
  app.use((err, req, res, next) => {
    const status = err.status >= 400 && err.status < 500 ? err.status : 500;
    res.status(status).json({ error: status === 500 ? 'Server error' : 'Bad request' });
  });

  return app;
}
