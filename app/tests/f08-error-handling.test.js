const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-08 No internal details leaked on error', () => {
  let token;

  beforeAll(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('a malformed ID never returns a stack trace or internal paths', async () => {
    const res = await request(BASE_URL).get('/api/wallets/not-a-valid-id').set('Authorization', `Bearer ${token}`);
    expect(res.body.stack).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toMatch(/node_modules|mongoose\/lib/);
  });
});
