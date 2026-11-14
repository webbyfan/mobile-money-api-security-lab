const jwt = require('jsonwebtoken');
const { reseed, login } = require('./helpers');

describe('F-10 JWT signing secret strength', () => {
  let token;

  beforeAll(async () => {
    reseed();
    token = await login('0911000001', 'alice-pass');
  });

  test('token cannot be verified with common/weak secrets', () => {
    const guesses = ['dev-only-placeholder', 'secret', 'changeme', 'password123'];
    for (const g of guesses) {
      expect(() => jwt.verify(token, g)).toThrow();
    }
  });

  test('token carries an expiry claim', () => {
    const decoded = jwt.decode(token);
    expect(decoded.exp).toBeDefined();
  });
});
