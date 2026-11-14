const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-05 Forgotten legacy transfer route', () => {
  let token;

  beforeAll(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('/api/v0/transfer no longer exists', async () => {
    const res = await request(BASE_URL)
      .post('/api/v0/transfer')
      .set('Authorization', `Bearer ${token}`)
      .send({ to: '0911000002', amount: 5 });
    expect(res.status).toBe(404);
  });
});
