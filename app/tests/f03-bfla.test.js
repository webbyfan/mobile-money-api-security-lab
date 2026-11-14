const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-03 BFLA - admin endpoints', () => {
  let aliceToken;

  beforeAll(async () => {
    reseed();
    aliceToken = await login('0911000001', 'alice-pass');
  });

  test('non-admin cannot list all users', async () => {
    const res = await request(BASE_URL).get('/api/admin/users').set('Authorization', `Bearer ${aliceToken}`);
    expect(res.status).toBe(403);
  });

  test('non-admin cannot adjust balances', async () => {
    const res = await request(BASE_URL)
      .post('/api/admin/adjust')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ userId: '000000000000000000000001', amount: 1000 });
    expect(res.status).toBe(403);
  });
});
