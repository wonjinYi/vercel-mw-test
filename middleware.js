import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { next } from '@vercel/functions';
import { loginPage } from './login-page.js';

// No path exclusions: HTML, assets, and direct file requests all require authentication.
export const config = { runtime: 'nodejs', matcher: '/:path*' };

const cacheHeaders = {
  'Cache-Control': 'private, no-store',
};

const loginPath = '/_auth/login';
const cookieName = '__Host-site_session';
const sessionSeconds = 8 * 60 * 60;

function textResponse(request, status, message, headers = {}) {
  return new Response(request.method === 'HEAD' ? null : message, {
    status,
    headers: {
      ...cacheHeaders,
      'Content-Type': 'text/plain; charset=utf-8',
      ...headers,
    },
  });
}

function matches(actual, expected) {
  const digest = (value) => createHash('sha256').update(value, 'utf8').digest();
  return timingSafeEqual(digest(actual), digest(expected));
}

function safeDestination(value, origin) {
  if (!value || !value.startsWith('/') || /[\\\u0000-\u0020\u007f]/.test(value)) return '/';
  try {
    const destination = new URL(value, origin);
    if (destination.origin !== origin || destination.pathname.startsWith('/_auth/')) return '/';
    return destination.pathname + destination.search;
  } catch {
    return '/';
  }
}

function showLogin(request, destination, status = 401, error = '') {
  return new Response(request.method === 'HEAD' ? null : loginPage(destination, error), {
    status,
    headers: {
      ...cacheHeaders,
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'Referrer-Policy': 'same-origin',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function signature(payload, key, origin) {
  return createHmac('sha256', key).update(`${origin}\n${payload}`).digest('hex');
}

function createSession(key, origin) {
  const issued = Math.floor(Date.now() / 1000);
  const payload = `v1.${issued}.${issued + sessionSeconds}.${randomBytes(16).toString('hex')}`;
  return `${payload}.${signature(payload, key, origin)}`;
}

function hasSession(request, key, origin) {
  const cookies = (request.headers.get('cookie') ?? '').split(';')
    .map((cookie) => cookie.trim()).filter((cookie) => cookie.startsWith(`${cookieName}=`));
  if (cookies.length !== 1) return false;
  const token = cookies[0].slice(cookieName.length + 1);
  const parts = /^(v1\.(\d{10})\.(\d{10})\.[a-f0-9]{32})\.([a-f0-9]{64})$/.exec(token);
  if (!parts) return false;
  const issued = Number(parts[2]);
  const expires = Number(parts[3]);
  const now = Math.floor(Date.now() / 1000);
  if (issued > now || expires <= now || expires - issued !== sessionSeconds) return false;
  return timingSafeEqual(Buffer.from(parts[4], 'hex'), Buffer.from(signature(parts[1], key, origin), 'hex'));
}

async function readForm(request) {
  const reader = request.body?.getReader();
  if (!reader) return new URLSearchParams();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8192) {
        await reader.cancel();
        throw new Error('Form too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
}

export default async function middleware(request) {
  // Keep the existing variable names so the configured username and password do not change.
  const user = process.env.BASIC_AUTH_USER;
  const password = process.env.BASIC_AUTH_PASSWORD;
  const secret = process.env.AUTH_SECRET;
  if (!user || !password || !secret || Buffer.byteLength(secret, 'utf8') < 32) {
    return textResponse(request, 503, 'Authentication is not configured.');
  }

  const url = new URL(request.url);
  // Rotating any credential invalidates existing sessions. Credentials never enter the token.
  const key = createHmac('sha256', secret).update(JSON.stringify(['site-session-v1', user, password])).digest();

  if (url.pathname === loginPath) {
    if (request.method === 'GET' || request.method === 'HEAD') {
      return showLogin(request, safeDestination(url.searchParams.get('next'), url.origin), 200);
    }
    if (request.method !== 'POST') {
      return textResponse(request, 405, 'Method not allowed.', { Allow: 'GET, HEAD, POST' });
    }
    // Same-origin form submissions prevent login CSRF. Do not trust forwarding headers.
    if (request.headers.get('origin') !== url.origin ||
        (request.headers.has('sec-fetch-site') && request.headers.get('sec-fetch-site') !== 'same-origin')) {
      return textResponse(request, 403, 'Request not allowed.');
    }
    if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') {
      return textResponse(request, 415, 'Unsupported form format.');
    }

    let form;
    try {
      form = await readForm(request);
    } catch {
      return textResponse(request, 400, 'Invalid login request.');
    }
    const destination = safeDestination(form.get('next'), url.origin);
    if (form.getAll('username').length !== 1 || form.getAll('password').length !== 1 || form.getAll('next').length > 1) {
      return showLogin(request, destination, 400, '입력 내용을 확인해 주세요.');
    }
    const userMatches = matches(form.get('username'), user);
    const passwordMatches = matches(form.get('password'), password);
    if (!userMatches || !passwordMatches) {
      return showLogin(request, destination, 401, '사용자이름 또는 비밀번호가 올바르지 않습니다.');
    }
    return new Response(null, {
      status: 303,
      headers: {
        ...cacheHeaders,
        Location: destination,
        'Set-Cookie': `${cookieName}=${createSession(key, url.origin)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${sessionSeconds}`,
      },
    });
  }

  if (hasSession(request, key, url.origin)) return next({ headers: cacheHeaders });
  return showLogin(request, safeDestination(url.pathname + url.search, url.origin));
}
