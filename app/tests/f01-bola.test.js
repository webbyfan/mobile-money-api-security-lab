const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-01 BOLA - wallet ownership', () => {
  let aliceToken, bobId;

  beforeAll(async () => {
    reseed();
    aliceToken = await login('0911000001', 'alice-pass');
    const bobToken = await login('0911000002', 'bob-pass');
    const me = await request(BASE_URL).get('/api/users/me').set('Authorization', `Bearer ${bobToken}`);
    bobId = me.body._id;
  });

  test("Alice cannot read Bob's wallet balance", async () => {
    const res = await request(BASE_URL).get(`/api/wallets/${bobId}`).set('Authorization', `Bearer ${aliceToken}`);
    expect(res.status).toBe(403);
  });

  test("Alice cannot read Bob's transaction history", async () => {
    const res = await request(BASE_URL).get(`/api/wallets/${bobId}/transactions`).set('Authorization', `Bearer ${aliceToken}`);
    expect(res.status).toBe(403);
  });
});
