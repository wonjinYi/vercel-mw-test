import assert from 'node:assert/strict';
import { afterEach, beforeEach, test } from 'node:test';
import middleware from './middleware.js';

const originalUser = process.env.BASIC_AUTH_USER;
const originalPassword = process.env.BASIC_AUTH_PASSWORD;
const testUser = 'test-user';
const testPassword = 'test-only:password:with-colons';
const encode = (value) => `Basic ${Buffer.from(value, 'utf8').toString('base64')}`;
const validAuth = encode(`${testUser}:${testPassword}`);

beforeEach(() => {
  process.env.BASIC_AUTH_USER = testUser;
  process.env.BASIC_AUTH_PASSWORD = testPassword;
});

afterEach(() => {
  for (const [key, value] of [
    ['BASIC_AUTH_USER', originalUser],
    ['BASIC_AUTH_PASSWORD', originalPassword],
  ]) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

function request(path = '/', authorization, options = {}) {
  const headers = new Headers(options.headers);
  if (authorization !== undefined) headers.set('Authorization', authorization);
  return new Request(`https://private.example${path}`, { ...options, headers });
}

async function assertDenied(response, method = 'GET', status = 401) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('x-middleware-next'), null);
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(await response.text(), method === 'HEAD' ? '' : status === 401
    ? 'Authentication required.' : 'Authentication is not configured.');
  if (status === 401) {
    assert.equal(response.headers.get('WWW-Authenticate'), 'Basic realm="Private Site", charset="UTF-8"');
  }
}

test('missing, wrong, and malformed credentials never continue to the HTML', async () => {
  const invalid = [
    undefined, '', 'Bearer arbitrary-token', 'Basic', 'Basic !!!', 'Basic a',
    'Basic YQ===', 'Basic YQ== extra', 'Basic /w==',
    encode('no-colon'), encode(':'), encode(`wrong:${testPassword}`),
    encode(`${testUser}:wrong`), encode(`${testUser}:${testPassword} `),
    encode(`${testUser.toUpperCase()}:${testPassword}`),
  ];
  for (const authorization of invalid) {
    await assertDenied(middleware(request('/', authorization)));
  }
});

test('direct files, assets, query strings, and alternate paths require authentication', async () => {
  const paths = [
    '/', '/index', '/index.html', '/index.html?download=1', '/index.html/',
    '/%69ndex.html', '/INDEX.html', '/assets/main.js', '/favicon.ico',
    '/.env', '/middleware.js', '/package.json', '/unknown',
  ];
  for (const path of paths) {
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'POST']) {
      await assertDenied(middleware(request(path, undefined, { method })), method);
    }
  }
});

test('client-supplied middleware and routing headers cannot grant access', async () => {
  for (const headers of [
    { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' },
    { 'x-middleware-next': '1' },
    { 'x-middleware-rewrite': 'https://private.example/index.html' },
    { 'x-original-url': '/index.html', 'x-rewrite-url': '/index.html' },
    { 'x-vercel-protection-bypass': 'arbitrary' },
  ]) {
    await assertDenied(middleware(request('/index.html', undefined, { headers })));
  }
});

test('correct credentials continue with no-store, including colon-containing passwords', () => {
  for (const path of ['/', '/index.html', '/assets/main.js']) {
    const response = middleware(request(path, validAuth));
    assert.equal(response.headers.get('x-middleware-next'), '1');
    assert.equal(response.headers.get('WWW-Authenticate'), null);
    assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  }
});

test('UTF-8 credentials and case-insensitive Basic scheme work', () => {
  process.env.BASIC_AUTH_USER = '사용자';
  process.env.BASIC_AUTH_PASSWORD = '테스트용:비밀번호';
  const authorization = encode('사용자:테스트용:비밀번호').replace('Basic ', 'bAsIc\t');
  assert.equal(middleware(request('/', authorization)).headers.get('x-middleware-next'), '1');
});

test('successful requests cannot authorize later anonymous or incorrect requests', async () => {
  assert.equal(middleware(request('/', validAuth)).headers.get('x-middleware-next'), '1');
  await assertDenied(middleware(request('/')));
  await assertDenied(middleware(request('/', encode(`${testUser}:wrong`))));
});

test('missing or empty configuration fails closed even with otherwise correct credentials', async () => {
  for (const key of ['BASIC_AUTH_USER', 'BASIC_AUTH_PASSWORD']) {
    for (const value of [undefined, '']) {
      process.env.BASIC_AUTH_USER = testUser;
      process.env.BASIC_AUTH_PASSWORD = testPassword;
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
      for (const method of ['GET', 'HEAD']) {
        await assertDenied(middleware(request('/', validAuth, { method })), method, 503);
      }
    }
  }
});

test('a username containing a colon fails closed', async () => {
  process.env.BASIC_AUTH_USER = 'invalid:user';
  await assertDenied(middleware(request('/', encode('invalid:user:password'))), 'GET', 503);
});
