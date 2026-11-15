const path = require('path');
const { execSync } = require('child_process');
const request = require('supertest');

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:3000';
const ROOT_DIR = path.join(__dirname, '..', '..');
const IS_CI = process.env.CI === 'true';

function reseed() {
  if (IS_CI) {
    execSync('node src/seed.js', {
      cwd: path.join(__dirname, '..'),
      stdio: 'ignore',
      env: { ...process.env },      // fix: forward MONGO_URI and friends to the child process
    });
  } else {
    execSync('docker compose exec -T api node src/seed.js', { cwd: ROOT_DIR, stdio: 'ignore' });
  }
}

function restartApi() {
  if (IS_CI) {
    return;
  }
  execSync('docker compose restart api', { cwd: ROOT_DIR, stdio: 'ignore' });
}

async function waitForHealthy(retries = 20) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await request(BASE_URL).get('/health');
      if (res.status === 200 && res.body.db) return;
    } catch (e) {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('API did not become healthy in time');
}

async function login(phone, password) {
  const res = await request(BASE_URL).post('/api/auth/login').send({ phone, password });
  return res.body.token;
}

module.exports = { request, BASE_URL, reseed, restartApi, waitForHealthy, login };
