const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-02 NoSQL injection & excessive data exposure', () => {
  let token;

  beforeAll(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('regex operator in phone query is rejected, not executed', async () => {
    const res = await request(BASE_URL)
      .get('/api/users/search')
      .query({ 'phone[$regex]': '.*' })
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });

  test('user profile never exposes passwordHash or pin fields', async () => {
    const res = await request(BASE_URL).get('/api/users/me').set('Authorization', `Bearer ${token}`);
    expect(res.body.passwordHash).toBeUndefined();
    expect(res.body.pinHash).toBeUndefined();
    expect(res.body.pin).toBeUndefined();
  });
});
