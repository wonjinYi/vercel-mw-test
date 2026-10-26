import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, test } from 'node:test';
import middleware from './middleware.js';
import { loginPage } from './login-page.js';

const origin = 'https://private.example';
const cookieName = '__Host-site_session';
const fixtures = {
  BASIC_AUTH_USER: 'test-user',
  BASIC_AUTH_PASSWORD: 'test-only:password:with-colons',
  AUTH_SECRET: 'test-only-secret-0123456789-abcdefghijklmnopqrstuvwxyz',
};
const previous = Object.fromEntries(Object.keys(fixtures).map((key) => [key, process.env[key]]));
const originalHtml = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
beforeEach(() => Object.assign(process.env, fixtures));
afterEach(() => {
  for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

const request = (path = '/', options = {}) => new Request(`${origin}${path}`, options);
const submit = (values = {}, headers = {}, body) => middleware(request('/_auth/login', {
  method: 'POST',
  headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
  body: body ?? new URLSearchParams({
    username: process.env.BASIC_AUTH_USER, password: process.env.BASIC_AUTH_PASSWORD, next: '/', ...values,
  }),
}));

async function login() {
  const response = await submit();
  assert.equal(response.status, 303);
  return response.headers.get('Set-Cookie').split(';')[0];
}

async function assertLogin(response, method = 'GET', status = 401) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('x-middleware-next'), null);
  assert.equal(response.headers.get('WWW-Authenticate'), null);
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(response.headers.get('Set-Cookie'), null);
  const html = await response.text();
  if (method === 'HEAD') assert.equal(html, '');
  else {
    assert.match(html, /<h1 id="login-title">로그인<\/h1>/);
    assert.match(html, /<form action="\/_auth\/login" method="post"/);
    assert.ok(!html.includes(originalHtml));
    assert.ok(!html.includes(fixtures.BASIC_AUTH_PASSWORD));
    assert.ok(!html.includes(fixtures.AUTH_SECRET));
    assert.ok(!html.includes('<script'));
  }
}

test('unauthenticated direct HTML, assets, alternate paths, and methods only receive login HTML', async () => {
  for (const path of ['/', '/index', '/index.html', '/index.html?download=1', '/index.html/',
    '/%69ndex.html', '/INDEX.html', '/assets/main.js', '/favicon.ico', '/.env', '/middleware.js', '/unknown']) {
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'POST']) {
      await assertLogin(await middleware(request(path, { method })), method);
    }
  }
});

test('login route displays a form without a Basic Auth dialog and rejects unsupported methods', async () => {
  await assertLogin(await middleware(request('/_auth/login')), 'GET', 200);
  await assertLogin(await middleware(request('/_auth/login', { method: 'HEAD' })), 'HEAD', 200);
  const response = await middleware(request('/_auth/login', { method: 'PUT' }));
  assert.equal(response.status, 405);
  assert.equal(response.headers.get('Allow'), 'GET, HEAD, POST');
});

test('old Basic Auth and client-supplied routing headers cannot grant access', async () => {
  for (const headers of [
    { Authorization: `Basic ${Buffer.from(`${fixtures.BASIC_AUTH_USER}:${fixtures.BASIC_AUTH_PASSWORD}`).toString('base64')}` },
    { 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' },
    { 'x-middleware-next': '1' }, { 'x-middleware-rewrite': `${origin}/index.html` },
    { 'x-original-url': '/index.html', 'x-rewrite-url': '/index.html' },
    { 'x-vercel-protection-bypass': 'arbitrary' },
  ]) await assertLogin(await middleware(request('/index.html', { headers })));
});

test('valid login creates a unique protected cookie and redirects to the requested page', async () => {
  const response = await submit({ next: '/index.html?view=1&lang=ko' });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('Location'), '/index.html?view=1&lang=ko');
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.equal(response.headers.get('WWW-Authenticate'), null);
  assert.equal(await response.text(), '');
  const cookie = response.headers.get('Set-Cookie');
  assert.match(cookie, /^__Host-site_session=v1\./);
  for (const attribute of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=28800']) {
    assert.ok(cookie.includes(attribute));
  }
  assert.ok(!cookie.includes('Domain='));
  for (const value of Object.values(fixtures)) assert.ok(!cookie.includes(value));
  assert.notEqual(cookie.split(';')[0], await login());
});

test('valid cookies allow pages and assets while anonymous requests remain blocked', async () => {
  const cookie = await login();
  for (const path of ['/', '/index.html', '/assets/main.js']) {
    for (const method of ['GET', 'HEAD']) {
      const response = await middleware(request(path, { method, headers: { Cookie: cookie } }));
      assert.equal(response.headers.get('x-middleware-next'), '1');
      assert.equal(response.headers.get('Set-Cookie'), null);
      assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
    }
  }
  await assertLogin(await middleware(request('/')));
});

test('incorrect credentials show a generic error and never issue a cookie', async () => {
  for (const values of [{ username: 'wrong' }, { password: 'wrong' }, { username: '', password: '' },
    { username: fixtures.BASIC_AUTH_USER.toUpperCase() }, { password: fixtures.BASIC_AUTH_PASSWORD + ' ' }]) {
    const response = await submit(values);
    assert.match(await response.clone().text(), /사용자이름 또는 비밀번호가 올바르지 않습니다/);
    await assertLogin(response);
  }
});

test('UTF-8 credentials and colons work', async () => {
  process.env.BASIC_AUTH_USER = '사용자:이름';
  process.env.BASIC_AUTH_PASSWORD = '테스트용:비밀번호';
  const cookie = await login();
  assert.equal((await middleware(request('/', { headers: { Cookie: cookie } }))).headers.get('x-middleware-next'), '1');
});

test('modified, malformed, or duplicate cookies cannot grant access', async () => {
  const cookie = await login();
  const modified = cookie.slice(0, -1) + (cookie.endsWith('0') ? '1' : '0');
  for (const invalid of [`${cookieName}=`, `${cookieName}=fake`, `${cookieName}=${'a'.repeat(4096)}`,
    modified, cookie.replace('v1.', 'v2.'), cookie.replace(/v1\.\d+\./, 'v1.9999999999.'),
    `${cookie}; ${cookie}`, `site_session=${cookie.split('=')[1]}`]) {
    await assertLogin(await middleware(request('/', { headers: { Cookie: invalid } })));
  }
});

test('cookies expire at eight hours and cannot be used before their issue time', async (context) => {
  const cookie = await login();
  const issued = Number(cookie.split('.')[1]);
  const clock = context.mock.method(Date, 'now', () => (issued + 28800 - 1) * 1000);
  assert.equal((await middleware(request('/', { headers: { Cookie: cookie } }))).headers.get('x-middleware-next'), '1');
  clock.mock.mockImplementation(() => (issued + 28800) * 1000);
  await assertLogin(await middleware(request('/', { headers: { Cookie: cookie } })));
  clock.mock.mockImplementation(() => (issued - 1) * 1000);
  await assertLogin(await middleware(request('/', { headers: { Cookie: cookie } })));
});

test('credential or signing-secret rotation invalidates existing sessions', async () => {
  const cookie = await login();
  for (const key of Object.keys(fixtures)) {
    Object.assign(process.env, fixtures);
    process.env[key] += '-changed';
    await assertLogin(await middleware(request('/', { headers: { Cookie: cookie } })));
  }
});

test('sessions cannot be reused on another origin', async () => {
  const cookie = await login();
  await assertLogin(await middleware(new Request('https://other.example/', { headers: { Cookie: cookie } })));
});

test('missing, empty, or short configuration fails closed on both page and login routes', async () => {
  const cookie = await login();
  for (const key of Object.keys(fixtures)) {
    for (const value of [undefined, '', ...(key === 'AUTH_SECRET' ? ['too-short'] : [])]) {
      Object.assign(process.env, fixtures);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
      for (const path of ['/', '/_auth/login']) {
        for (const method of ['GET', 'HEAD']) {
          const response = await middleware(request(path, { method, headers: { Cookie: cookie } }));
          assert.equal(response.status, 503);
          assert.equal(response.headers.get('x-middleware-next'), null);
          assert.equal(await response.text(), method === 'HEAD' ? '' : 'Authentication is not configured.');
        }
      }
    }
  }
});

test('cross-origin and origin-less login attempts are rejected even with valid credentials', async () => {
  for (const headers of [{ Origin: 'https://evil.example' }, { Origin: 'null' }, { Origin: '' },
    { Origin: 'https://evil.example', 'x-forwarded-host': 'private.example' },
    { 'Sec-Fetch-Site': 'cross-site' }, { 'Sec-Fetch-Site': 'same-site' }]) {
    const response = await submit({}, headers);
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('Set-Cookie'), null);
  }
  assert.equal((await submit({}, { 'Sec-Fetch-Site': 'same-origin' })).status, 303);
});

test('malformed or oversized forms are rejected without issuing cookies', async () => {
  assert.equal((await submit({}, { 'Content-Type': 'application/json' }, '{}')).status, 415);
  for (const body of ['', `username=${fixtures.BASIC_AUTH_USER}`, 'username=a&username=b&password=p',
    'username=u&password=a&password=b', 'username=u&password=p&next=/&next=//evil.example',
    'a'.repeat(8193), Buffer.from([0xff])]) {
    const response = await submit({}, {}, body);
    assert.equal(response.status, 400);
    assert.equal(response.headers.get('Set-Cookie'), null);
    assert.equal(response.headers.get('x-middleware-next'), null);
  }
});

test('login redirects cannot leave the origin or loop into authentication routes', async () => {
  for (const target of ['https://evil.example/', '//evil.example/', '/\\evil.example/', '/_auth/login',
    '/_auth/login?next=/', 'javascript:alert(1)', '/\r\nLocation:https://evil.example']) {
    assert.equal((await submit({ next: target })).headers.get('Location'), '/');
  }
});

test('HTML escapes reflected content, blocks scripts, and loads no external assets', async () => {
  const html = loginPage('/" autofocus onfocus="alert(1)', '<script>alert(1)</script>');
  assert.ok(html.includes('/&quot; autofocus onfocus=&quot;alert(1)'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!html.includes('<script>'));
  assert.ok(!/\b(?:src|href)=/.test(html));
  const response = await middleware(request('/index.html?view=1&lang=ko'));
  assert.match(await response.text(), /value="\/index.html\?view=1&amp;lang=ko"/);
  assert.match(response.headers.get('Content-Security-Policy'), /form-action 'self'/);
  // no-referrer can turn a browser form's Origin into "null" and break the CSRF check.
  assert.equal(response.headers.get('Referrer-Policy'), 'same-origin');
});
