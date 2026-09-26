// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// TODO — yours to implement.
//
// Verify an access token and return its claims, or throw `unauthenticated(...)`.
// The signing half above is done for you; the verifying half is the exercise.
//
// It must reject ALL of the following, each with a 401 UNAUTHENTICATED:
//
//   1. a token that is not three dot-separated segments
//   2. a header or payload that is not valid base64url-encoded JSON
//   3. a header whose `alg` is anything other than 'HS256', or whose `typ` is not 'JWT'
//      -- read the header, do NOT trust it. This is the `alg: none` and
//         algorithm-substitution defence. The constants ALG, ISS and AUD are above.
//   4. a signature that does not match, compared in constant time
//   5. an `exp` that is missing, not a number, or <= now (note: <=, not <)
//   6. an `iss` or `aud` that is not ours
//   7. a missing or empty `jti`
//
// On success, return the decoded claims object.
//
// AUTH-DATA-MODEL.md §10 lists the failure modes; §2 defines the claim set.
// `node scripts/check-jwt.js` is the public test suite for this function.
// ---------------------------------------------------------------------------
export function verifyAccessToken(token, secret) {
  try {
    // 1. Token must contain exactly 3 segments
    if (typeof token !== 'string') {
      throw unauthenticated('invalid access token');
    }

    const parts = token.split('.');

    if (parts.length !== 3) {
      throw unauthenticated('invalid access token');
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    // Helper for strict base64url validation
    const decodeJson = (value) => {
      if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length % 4 === 1 ||
        !/^[A-Za-z0-9_-]+$/.test(value)
      ) {
        throw new Error('invalid base64url');
      }

      const decoded = unb64(value).toString('utf8');
      return JSON.parse(decoded);
    };

    // 2. Decode and parse header + payload
    const header = decodeJson(encodedHeader);
    const claims = decodeJson(encodedPayload);

    // 3. Check algorithm and token type
    if (
      !header ||
      typeof header !== 'object' ||
      header.alg !== ALG ||
      header.typ !== 'JWT'
    ) {
      throw unauthenticated('invalid access token');
    }

    // 4. Verify signature
    if (
      typeof encodedSignature !== 'string' ||
      encodedSignature.length === 0 ||
      encodedSignature.length % 4 === 1 ||
      !/^[A-Za-z0-9_-]+$/.test(encodedSignature)
    ) {
      throw unauthenticated('invalid access token');
    }

    const actualSignature = unb64(encodedSignature);

    const expectedSignature = createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest();

    // timingSafeEqual requires buffers of the same length.
    const comparison = Buffer.alloc(expectedSignature.length);
    actualSignature.copy(
      comparison,
      0,
      0,
      Math.min(actualSignature.length, comparison.length)
    );

    const signatureMatches =
      actualSignature.length === expectedSignature.length &&
      timingSafeEqual(comparison, expectedSignature);

    if (!signatureMatches) {
      throw unauthenticated('invalid access token');
    }

    // 5. Validate expiration
    const now = Math.floor(Date.now() / 1000);

    if (
      typeof claims.exp !== 'number' ||
      !Number.isFinite(claims.exp) ||
      claims.exp <= now
    ) {
      throw unauthenticated('invalid access token');
    }

    // 6. Validate issuer and audience
    if (claims.iss !== ISS || claims.aud !== AUD) {
      throw unauthenticated('invalid access token');
    }

    // 7. jti must exist and not be empty
    if (
      typeof claims.jti !== 'string' ||
      claims.jti.trim() === ''
    ) {
      throw unauthenticated('invalid access token');
    }

    // Everything passed
    return claims;
  } catch (error) {
    // Preserve our intended 401 error
    if (error?.code === 'UNAUTHENTICATED') {
      throw error;
    }

    // Convert malformed token/JSON/etc. into 401
    throw unauthenticated('invalid access token');
  }
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
