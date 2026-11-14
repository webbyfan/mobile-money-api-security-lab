const crypto = require('crypto');

function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pw), salt, 32).toString('hex');
}

function verify(pw, stored) {
  const [salt, h] = stored.split(':');
  const calc = crypto.scryptSync(String(pw), salt, 32);
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), calc);
}

module.exports = { hash, verify };
