import { randomBytes } from 'node:crypto';
import * as flawedDb from '../flawed/db.js';
import * as fixedDb from '../fixed/db.js';
import { createApp as createFlawed } from '../flawed/app.js';
import { createApp as createFixed } from '../fixed/app.js';

// Starts one version of the API on a free port with fresh seeded data.
export async function start(version, options = {}) {
  const { openDb, seed } = version === 'flawed' ? flawedDb : fixedDb;
  const db = openDb();
  seed(db);
  const app =
    version === 'flawed'
      ? createFlawed(db)
      : createFixed(db, { jwtSecret: randomBytes(32).toString('hex'), ...options });
  const outbox = [];
  app.locals.sendResetEmail = (email, token) => outbox.push({ email, token });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(method, path, { token, body } = {}) {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(body !== undefined && { 'content-type': 'application/json' }),
        ...(token && { authorization: `Bearer ${token}` }),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  }

  async function login(email, password) {
    const res = await call('POST', '/api/login', { body: { email, password } });
    if (res.status !== 200) throw new Error(`login failed for ${email}: ${res.status}`);
    return res.body.token;
  }

  return { db, base, call, login, outbox, close: () => new Promise((r) => server.close(r)) };
}

export const BOB = ['bob@acme.test', 'bob-password-1'];
export const ALICE = ['alice@acme.test', 'alice-password-1'];
