// Ordinary use must keep working on both versions: the fixes may not break the app.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { start, BOB, ALICE } from './helpers.js';

for (const version of ['flawed', 'fixed']) {
  test(`${version}: a member lists, reads and deletes his own company's documents`, async () => {
    const api = await start(version);
    const bob = await api.login(...BOB);
    const list = await api.call('GET', '/api/documents', { token: bob });
    assert.deepEqual(list.body.map((d) => d.title), ['Acme pricing 2027']);
    const doc = await api.call('GET', '/api/documents/1', { token: bob });
    assert.equal(doc.body.body, 'Enterprise tier at 1,200 EUR a month.');
    assert.equal((await api.call('DELETE', '/api/documents/1', { token: bob })).status, 204);
    await api.close();
  });

  test(`${version}: a member renames himself and sees his team`, async () => {
    const api = await start(version);
    const bob = await api.login(...BOB);
    const me = await api.call('PATCH', '/api/me', { token: bob, body: { name: 'Robert' } });
    assert.equal(me.status, 200);
    assert.equal(me.body.name, 'Robert');
    const team = await api.call('GET', '/api/team', { token: bob });
    assert.deepEqual(team.body.map((u) => u.email).sort(), [ALICE[0], BOB[0]]);
    await api.close();
  });

  test(`${version}: a forgotten password is reset with the emailed token`, async () => {
    const api = await start(version);
    await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
    const token =
      version === 'fixed'
        ? api.outbox.at(-1).token
        : api.db.prepare('SELECT reset_token FROM users WHERE id = 1').get().reset_token;
    const reset = await api.call('POST', '/api/password/reset', { body: { token, password: 'a-new-long-password' } });
    assert.equal(reset.status, 200);
    assert.ok(await api.login(ALICE[0], 'a-new-long-password'));
    await api.close();
  });
}

test('fixed: a reset token works once and ends the sessions opened before it', async () => {
  const api = await start('fixed');
  const oldSession = await api.login(...ALICE);
  await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
  const token = api.outbox.at(-1).token;
  assert.equal((await api.call('POST', '/api/password/reset', { body: { token, password: 'a-new-long-password' } })).status, 200);
  assert.equal((await api.call('POST', '/api/password/reset', { body: { token, password: 'another-password' } })).status, 400);
  assert.equal((await api.call('GET', '/api/me', { token: oldSession })).status, 401);
  await api.close();
});

test('fixed: malformed JSON gets a JSON 400, and passwords over 72 bytes are refused', async () => {
  const api = await start('fixed');
  const res = await fetch(api.base + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"email":',
  });
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: 'Bad request' });
  assert.equal(res.headers.get('x-powered-by'), null);
  await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
  const token = api.outbox.at(-1).token;
  assert.equal((await api.call('POST', '/api/password/reset', { body: { token, password: 'x'.repeat(73) } })).status, 400);
  await api.close();
});

test('fixed: the forgot-password answer does not say whether an email exists', async () => {
  const api = await start('fixed');
  const known = await api.call('POST', '/api/password/forgot', { body: { email: ALICE[0] } });
  const unknown = await api.call('POST', '/api/password/forgot', { body: { email: 'nobody@acme.test' } });
  assert.deepEqual(known, unknown);
  assert.equal(api.outbox.length, 1);
  await api.close();
});
