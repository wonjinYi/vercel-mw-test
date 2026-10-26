import { createHash, timingSafeEqual } from 'node:crypto';
import { next } from '@vercel/functions';

// No path exclusions: HTML, assets, and direct file requests all require authentication.
export const config = { runtime: 'nodejs', matcher: '/:path*' };

const cacheHeaders = {
  'Cache-Control': 'private, no-store',
};

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

export default function middleware(request) {
  const expectedUser = process.env.BASIC_AUTH_USER;
  const expectedPassword = process.env.BASIC_AUTH_PASSWORD;

  // A missing configuration must never make the site public.
  if (!expectedUser || !expectedPassword || expectedUser.includes(':')) {
    return textResponse(request, 503, 'Authentication is not configured.');
  }

  const authorization = request.headers.get('authorization') ?? '';
  const match = /^Basic[ \t]+([A-Za-z0-9+/]+={0,2})[ \t]*$/i.exec(authorization);

  if (match) {
    try {
      // atob rejects malformed Base64. Fatal UTF-8 decoding prevents replacement characters.
      const bytes = Uint8Array.from(atob(match[1]), (character) => character.charCodeAt(0));
      const credentials = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const separator = credentials.indexOf(':');

      if (separator !== -1) {
        const userMatches = matches(credentials.slice(0, separator), expectedUser);
        const passwordMatches = matches(credentials.slice(separator + 1), expectedPassword);

        if (userMatches && passwordMatches) {
          return next({ headers: cacheHeaders });
        }
      }
    } catch {
      // Malformed credentials receive the same challenge as incorrect credentials.
    }
  }

  return textResponse(request, 401, 'Authentication required.', {
    'WWW-Authenticate': 'Basic realm="Private Site", charset="UTF-8"',
  });
}
