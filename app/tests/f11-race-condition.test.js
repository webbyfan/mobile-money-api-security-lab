const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-11 Race condition / double-spend prevention', () => {
  beforeEach(() => {
    reseed();
  });

  test('only one of 20 concurrent transfers succeeds', async () => {
    const token = await login('0911000001', 'alice-pass');
    const body = { to: '0911000002', amount: 600, pin: '1234' };

    const results = await Promise.all(
      Array.from({ length: 20 }).map(() =>
        request(BASE_URL).post('/api/transfer').set('Authorization', `Bearer ${token}`).send(body)
      )
    );
    const successes = results.filter((r) => r.status === 200).length;
    expect(successes).toBe(1);

    const me = await request(BASE_URL).get('/api/users/me').set('Authorization', `Bearer ${token}`);
    expect(me.body.balance).toBe(400);
  }, 30000);
});
