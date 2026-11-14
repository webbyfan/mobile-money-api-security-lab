const { request, BASE_URL, reseed, login } = require('./helpers');

describe('F-07 SSRF protection on webhook test endpoint', () => {
  let token;

  beforeAll(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('internal non-https URL is rejected', async () => {
    const res = await request(BASE_URL)
      .post('/api/users/me/webhook/test')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'http://mongo:27017' });
    expect(res.status).toBe(400);
  });

  test('private IP range URL is rejected even over https', async () => {
    const res = await request(BASE_URL)
      .post('/api/users/me/webhook/test')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://127.0.0.1/secret' });
    expect(res.status).toBe(400);
  });
});
