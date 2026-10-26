// Each attack runs against flawed/ (it must work) and fixed/ (it must be refused).
// An attack "works" only through its assertions: a crash fails the test either way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { start, BOB, ALICE } from './helpers.js';
import { loadSecret } from '../fixed/auth.js';

// The fallback string from flawed/auth.js, as anyone reading the repository sees it.
const LEAKED_FALLBACK = 'super-secret-key-change-me';

test('1 flawed: a token signed with the fallback secret opens another company', async () => {
  const api = await start('flawed');
  const forged = jwt.sign({ id: 3, email: 'carol@globex.test', role: 'owner', workspace_id: 2 }, LEAKED_FALLBACK);
  const res = await api.call('GET', '/api/documents', { token: forged });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.map((d) => d.title), ['Globex acquisition memo']);
  await api.close();
});

test('1 fixed: forged tokens are refused and the server will not start without a real secret', async () => {
  const api = await start('fixed');
  for (const claims of [
    { sub: '3', tv: 0 },
    { id: 3, role: 'owner', workspace_id: 2 },
  ]) {
    const res = await api.call('GET', '/api/documents', { token: jwt.sign(claims, LEAKED_FALLBACK) });
    assert.equal(res.status, 401);
  }
  assert.throws(() => loadSecret(undefined), /JWT_SECRET/);
  assert.throws(() => loadSecret(LEAKED_FALLBACK), /JWT_SECRET/);
  await api.close();
  // The app itself refuses to build without a real secret, not only server.js.
  await assert.rejects(() => start('fixed', { jwtSecret: undefined }), /JWT_SECRET/);
  await assert.rejects(() => start('fixed', { jwtSecret: LEAKED_FALLBACK }), /JWT_SECRET/);
});

test('1 fixed: role and company come from the database, not from the token', async () => {
  const secret = 'a'.repeat(16) + 'b'.repeat(16) + 'c'.repeat(16);
  const api = await start('fixed', { jwtSecret: secret });
  const bobClaims = { sub: '2', tv: 0, id: 2, role: 'owner', workspace_id: 2 };
  const token = jwt.sign(bobClaims, secret, { algorithm: 'HS256' });
  const docs = await api.call('GET', '/api/documents', { token });
  assert.equal(docs.status, 200);
  assert.deepEqual(docs.body.map((d) => d.title), ['Acme pricing 2027']);
  assert.equal((await api.call('GET', '/api/me', { token })).body.role, 'member');
  await api.close();
});

test('2 flawed: a member reads and deletes another company\'s document by id', async () => {
  const api = await start('flawed');
  const bob = await api.login(...BOB);
  const read = await api.call('GET', '/api/documents/2', { token: bob });
  assert.equal(read.status, 200);
  assert.equal(read.body.title, 'Globex acquisition memo');
  assert.equal((await api.call('DELETE', '/api/documents/2', { token: bob })).status, 204);
  assert.equal(api.db.prepare('SELECT count(*) AS n FROM documents WHERE id = 2').get().n, 0);
  await api.close();
});

test('2 fixed: another company\'s document answers 404 and stays', async () => {
  const api = await start('fixed');
  const bob = await api.login(...BOB);
  assert.equal((await api.call('GET', '/api/documents/2', { token: bob })).status, 404);
  assert.equal((await api.call('DELETE', '/api/documents/2', { token: bob })).status, 404);
  assert.equal(api.db.prepare('SELECT count(*) AS n FROM documents WHERE id = 2').get().n, 1);
  await api.close();
});

test('3 flawed: a member makes himself owner, moves to another company, and injects SQL through a field name', async () => {
  const api = await start('flawed');
  let bob = await api.login(...BOB);
  const promoted = await api.call('PATCH', '/api/me', { token: bob, body: { role: 'owner' } });
  assert.equal(promoted.body.role, 'owner');

  await api.call('PATCH', '/api/me', { token: bob, body: { workspace_id: 2 } });
  bob = await api.login(...BOB);
  const docs = await api.call('GET', '/api/documents', { token: bob });
  assert.deepEqual(docs.body.map((d) => d.title), ['Globex acquisition memo']);

  // Field names are pasted into the SQL: this one copies Bob's password hash onto Alice.
  const injection = "password_hash = (SELECT password_hash FROM users WHERE id = ?) WHERE email = 'alice@acme.test' OR id = ? --";
  assert.equal((await api.call('PATCH', '/api/me', { token: bob, body: { [injection]: 2 } })).status, 200);
  const asAlice = await api.call('POST', '/api/login', { body: { email: ALICE[0], password: BOB[1] } });
  assert.equal(asAlice.status, 200);
  await api.close();
});

test('3 fixed: only the name is editable; role, workspace and SQL in field names are refused', async () => {
  const api = await start('fixed');
  const bob = await api.login(...BOB);
  const injection = "password_hash = (SELECT password_hash FROM users WHERE id = ?) WHERE email = 'alice@acme.test' OR id = ? --";
  for (const body of [{ role: 'owner' }, { workspace_id: 2 }, { name: 'Bob', role: 'owner' }, { [injection]: 2 }]) {
    assert.equal((await api.call('PATCH', '/api/me', { token: bob, body })).status, 400);
  }
  const me = await api.call('GET', '/api/me', { token: bob });
  assert.equal(me.body.role, 'member');
  assert.equal(me.body.workspace_id, 1);
  assert.equal((await api.call('POST', '/api/login', { body: { email: ALICE[0], password: BOB[1] } })).status, 401);
  await api.close();
});

test('4 flawed: a member takes over the owner\'s account through the team list', async () => {
  const api = await start('flawed');
  const bob = await api.login(...BOB);
  await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
  const team = await api.call('GET', '/api/team', { token: bob });
  const alice = team.body.find((u) => u.email === ALICE[0]);
  assert.match(alice.password_hash, /^\$2[aby]\$/);
  assert.ok(alice.reset_token);
  const reset = await api.call('POST', '/api/password/reset', { body: { token: alice.reset_token, password: 'owned-by-bob' } });
  assert.equal(reset.status, 200);
  const asAlice = await api.call('POST', '/api/login', { body: { email: ALICE[0], password: 'owned-by-bob' } });
  assert.equal(asAlice.status, 200);
  await api.close();
});

test('4 fixed: the team list shows no secrets, and reset tokens are hashed, single-use and short-lived', async () => {
  let clock = Date.now();
  const api = await start('fixed', { now: () => clock });
  const bob = await api.login(...BOB);
  await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
  const team = await api.call('GET', '/api/team', { token: bob });
  assert.equal(team.body.length, 2);
  for (const user of team.body) {
    assert.deepEqual(Object.keys(user).sort(), ['email', 'id', 'name', 'role', 'workspace_id']);
  }
  const stored = api.db.prepare('SELECT reset_token_hash FROM users WHERE id = 1').get().reset_token_hash;
  const emailed = api.outbox.at(-1).token;
  assert.notEqual(stored, emailed);
  assert.equal((await api.call('POST', '/api/password/reset', { body: { token: stored, password: 'owned-by-bob' } })).status, 400);

  clock += 31 * 60 * 1000;
  assert.equal((await api.call('POST', '/api/password/reset', { body: { token: emailed, password: 'owned-by-bob' } })).status, 400);
  await api.close();
});
