const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-04 Mass assignment - privilege escalation', () => {
  let token;

  beforeEach(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('cannot set own role or balance via PATCH /users/me', async () => {
    const res = await request(BASE_URL)
      .patch('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'admin', balance: 999999 });
    expect(res.status).toBe(400);
  });

  test('role and balance remain unchanged after an escalation attempt', async () => {
    await request(BASE_URL)
      .patch('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'admin', balance: 999999 });
    const me = await request(BASE_URL).get('/api/users/me').set('Authorization', `Bearer ${token}`);
    expect(me.body.role).toBe('user');
    expect(me.body.balance).toBe(1000);
  });
});
