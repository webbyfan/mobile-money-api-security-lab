const { request, BASE_URL, reseed, restartApi, waitForHealthy } = require('./helpers');

describe('F-09 Login rate limiting', () => {
  beforeAll(() => {
    reseed();
  });

  test('blocks after repeated failed login attempts', async () => {
    let lastStatus;
    for (let i = 0; i < 12; i++) {
      const res = await request(BASE_URL).post('/api/auth/login').send({ phone: '0911000001', password: 'wrong' });
      lastStatus = res.status;
      if (i < 9) expect(res.status).toBe(401);
    }
    expect(lastStatus).toBe(429);
  }, 20000);

  // Reset the in-memory limiter so later test files aren't blocked by this one.
  afterAll(async () => {
    restartApi();
    await waitForHealthy();
  }, 30000);
});
