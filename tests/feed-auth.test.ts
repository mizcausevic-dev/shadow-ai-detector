import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { request as httpRequest, type Server } from 'node:http';
import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from 'jose';
import { app, createApp } from '../src/index';
import type { FeedBoundaryConfig } from '../src/security/feed-boundary';

const issuer = 'https://identity.example.test/';
const audience = 'shadow-feed-pilot';
const resourceId = 'feed_alpha';
const tenantId = 'tenant_alpha';
const fixtureEvent = {
  eventId: 'synthetic_1', timestamp: '2026-05-07T12:00:00Z',
  url: 'https://api.openai.com/v1/chat/completions', method: 'POST',
  payloadSnippet: 'public synthetic sample', user: 'sample@example.test',
  department: 'synthetic', sourceHost: '127.0.0.1', bytesUp: 20, bytesDown: 10,
};

let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let untrustedPrivateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let publicKeys: JSONWebKeySet;
let feedConfig: FeedBoundaryConfig;
let server: Server;
let baseUrl: string;
let defaultServer: Server;
let defaultUrl: string;
const revoked = new Set<string>();
const resourceOwners = new Map([[resourceId, tenantId], ['feed_beta', tenantId], ['feed_other', 'tenant_other']]);
const resourceGrants = new Map([[resourceId, new Set(['synthetic-client'])]]);
let statusFails = false;
let lookupFails = false;
let grantFails = false;

before(async () => {
  const pair = await generateKeyPair('EdDSA', { extractable: true });
  untrustedPrivateKey = (await generateKeyPair('EdDSA')).privateKey;
  privateKey = pair.privateKey;
  publicKeys = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'test-key', alg: 'EdDSA', use: 'sig' }] };
  feedConfig = {
    issuer, audience, publicKeys,
    isTokenActive: async (principal) => {
      if (statusFails) throw new Error('simulated status outage');
      return !revoked.has(principal.tokenId);
    },
    tenantForResource: async (id) => {
      if (lookupFails) throw new Error('simulated registry outage');
      return resourceOwners.get(id) ?? null;
    },
    isClientAllowedForResource: async (principal, id) => {
      if (grantFails) throw new Error('simulated grant outage');
      return resourceGrants.get(id)?.has(principal.clientId) ?? false;
    },
  };
  server = createApp(feedConfig).listen(0, '127.0.0.1');
  defaultServer = app.listen(0, '127.0.0.1');
  await Promise.all([
    new Promise<void>((resolve) => server.once('listening', resolve)),
    new Promise<void>((resolve) => defaultServer.once('listening', resolve)),
  ]);
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  defaultUrl = `http://127.0.0.1:${(defaultServer.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  defaultServer.close();
});

async function token(overrides: {
  issuer?: string; audience?: string | string[]; tenant?: string; scope?: string;
  tokenId?: string; issuedAt?: number; expiresAt?: number; typ?: string;
  keyId?: string; signingKey?: typeof privateKey; subject?: string; clientId?: string;
} = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    tenant_id: overrides.tenant ?? tenantId,
    client_id: overrides.clientId ?? 'synthetic-client',
    scope: overrides.scope ?? 'shadow:feed:analyze',
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: overrides.keyId ?? 'test-key', typ: overrides.typ ?? 'at+jwt' })
    .setIssuer(overrides.issuer ?? issuer)
    .setAudience(overrides.audience ?? audience)
    .setSubject(overrides.subject ?? 'synthetic-caller')
    .setJti(overrides.tokenId ?? 'token-1')
    .setIssuedAt(overrides.issuedAt ?? now)
    .setExpirationTime(overrides.expiresAt ?? now + 120)
    .sign(overrides.signingKey ?? privateKey);
}

async function analyze(bearer?: string, url = baseUrl, body: string = JSON.stringify({ events: [fixtureEvent] }), id = resourceId) {
  return fetch(`${url}/api/feed/${id}/analyze/traffic`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }),
    },
    body,
  });
}

async function analyzeWithDuplicateAuthorization(bearer: string): Promise<number | 'reset' | undefined> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(`${baseUrl}/api/feed/${resourceId}/analyze/traffic`, {
      method: 'POST',
      headers: [
        'content-type', 'application/json',
        'authorization', `Bearer ${bearer}`,
        'Authorization', `Bearer ${bearer}`,
      ],
    }, (response) => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
    });
    request.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ECONNRESET') resolve('reset');
      else reject(error);
    });
    request.end(JSON.stringify({ events: [fixtureEvent] }));
  });
}

test('normal local runtime has no enabled feed route', async () => {
  const response = await analyze(await token(), defaultUrl);
  assert.equal(response.status, 404);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('configured path verifies a token and server-owned tenant before analysis', async () => {
  const response = await analyze(await token());
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json() as { dataMode: string; summary: { totalEvents: number } };
  assert.equal(body.dataMode, 'caller-supplied-unverified');
  assert.equal(body.summary.totalEvents, 1);
  const bypass = await fetch(`${baseUrl}/api/analyze/traffic`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ events: [fixtureEvent] }),
  });
  assert.equal(bypass.status, 404);
  for (const fixturePath of ['/preview', '/api/endpoints', '/api/incidents', '/api/dashboard/summary']) {
    assert.equal((await fetch(`${baseUrl}${fixturePath}`)).status, 404, fixturePath);
  }
});

test('missing or malformed bearer is denied before body parsing', async () => {
  for (const bearer of [undefined, '', 'not-a-jwt']) {
    const response = await analyze(bearer, baseUrl, '{invalid');
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
  const accepted = await analyze(await token(), baseUrl, '{invalid');
  assert.equal(accepted.status, 400);
  // Node may reject duplicate Authorization fields at HTTP parsing (400 or
  // connection reset) before middleware can reject them (401).
  assert.ok([400, 401, 'reset'].includes(await analyzeWithDuplicateAuthorization(await token()) ?? 0));
  assert.equal((await fetch(`${baseUrl}/health`)).status, 200);
});

test('wrong issuer, audience, age, expiry, type, or scope is denied', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const claims of [
    { issuer: 'https://other.example.test/' },
    { audience: 'another-service' },
    { audience: [audience, 'another-service'] },
    { issuedAt: now - 600, expiresAt: now + 30 },
    { issuedAt: now - 600, expiresAt: now - 500 },
    { typ: 'JWT' },
    { scope: 'shadow:feed:read' },
    { keyId: 'unknown-key' },
    { signingKey: untrustedPrivateKey },
  ]) {
    const response = await analyze(await token(claims));
    assert.equal(response.status, 401);
  }
});

test('revocation and status outage deny valid signed tokens', async () => {
  revoked.add('revoked-token');
  assert.equal((await analyze(await token({ tokenId: 'revoked-token' }))).status, 401);
  statusFails = true;
  try {
    assert.equal((await analyze(await token())).status, 401);
  } finally {
    statusFails = false;
    revoked.clear();
  }
});

test('cross-tenant, missing resource, and registry outage deny analysis', async () => {
  const signed = await token();
  assert.equal((await analyze(signed, baseUrl, undefined, 'feed_other')).status, 403);
  assert.equal((await analyze(signed, baseUrl, undefined, 'feed_missing')).status, 403);
  assert.equal((await analyze(await token({ tenant: 'tenant_other' }))).status, 403);
  lookupFails = true;
  try {
    assert.equal((await analyze(signed)).status, 401);
  } finally {
    lookupFails = false;
  }
});

test('same-subject different client and same-tenant ungranted resource are denied', async () => {
  assert.equal((await analyze(await token({ clientId: 'ungranted-client' }))).status, 403);
  assert.equal((await analyze(await token(), baseUrl, undefined, 'feed_beta')).status, 403);
  grantFails = true;
  try {
    assert.equal((await analyze(await token())).status, 401);
  } finally {
    grantFails = false;
  }
});

test('invalid identity configuration is rejected before an app is created', () => {
  const callbacks = {
    isTokenActive: async () => true,
    tenantForResource: async () => tenantId,
    isClientAllowedForResource: async () => true,
  };
  assert.throws(() => createApp({ issuer: 'http://identity.example.test', audience, publicKeys, ...callbacks }));
  assert.throws(() => createApp({ issuer, audience, publicKeys: { keys: [] }, ...callbacks }));
  assert.throws(() => createApp({ issuer, audience, publicKeys: { keys: [{ kty: 'oct', kid: 'test-key' }] }, ...callbacks }));
});

test('configured feed rejects request bursts before authorization or body parsing', async () => {
  const isolated = createApp(feedConfig).listen(0, '127.0.0.1');
  try {
    await new Promise<void>((resolve) => isolated.once('listening', resolve));
    const url = `http://127.0.0.1:${(isolated.address() as AddressInfo).port}`;
    const responses = await Promise.all(Array.from({ length: 100 }, async () => {
      const response = await fetch(`${url}/api/feed/${resourceId}/analyze/traffic`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{invalid',
      });
      return {
        status: response.status,
        cacheControl: response.headers.get('cache-control'),
        retryAfter: response.headers.get('retry-after'),
      };
    }));
    const statuses = responses.map((response) => response.status);
    assert.ok(statuses.includes(401), 'requests below the quota still reach authorization');
    const throttled = responses.find((response) => response.status === 429);
    assert.ok(throttled, 'malformed JSON in a burst must be throttled before parsing');
    assert.ok(statuses.every((status) => status === 401 || status === 429));
    assert.equal(throttled.cacheControl, 'no-store');
    assert.equal(throttled.retryAfter, '1');
    assert.equal((await fetch(`${url}/health`)).status, 200);
  } finally {
    isolated.closeAllConnections();
    await new Promise<void>((resolve, reject) => isolated.close((error) => error ? reject(error) : resolve()));
  }
});
