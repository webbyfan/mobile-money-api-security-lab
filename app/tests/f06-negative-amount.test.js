const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-06 Negative-amount transfer', () => {
  let token;

  beforeEach(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('negative amount is rejected', async () => {
    const res = await request(BASE_URL)
      .post('/api/transfer')
      .set('Authorization', `Bearer ${token}`)
      .send({ to: '0911000002', amount: -50, pin: '1234' });
    expect(res.status).toBe(400);
  });

  test('balances are unaffected after a rejected negative transfer', async () => {
    await request(BASE_URL)
      .post('/api/transfer')
      .set('Authorization', `Bearer ${token}`)
      .send({ to: '0911000002', amount: -50, pin: '1234' });
    const me = await request(BASE_URL).get('/api/users/me').set('Authorization', `Bearer ${token}`);
    expect(me.body.balance).toBe(1000);
  });
});
