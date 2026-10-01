import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { request as httpRequest, type Server } from 'node:http';
import { app } from '../src/index';
import type { Request } from 'express';
import { canStartLocalDemo, isLocalDemoRequest } from '../src/config/local-boundary';

let server: Server;
let baseUrl: string;
before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => server.close());

const get = (path: string) => fetch(new URL(path, baseUrl));
const post = (path: string, body: unknown) => fetch(new URL(path, baseUrl), {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});

function getWithHeaders(path: string, headers: Record<string, string>): Promise<{
  status: number | undefined; body: string; cacheControl: string | undefined;
}> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, baseUrl), { headers }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk: string) => { body += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        body,
        cacheControl: response.headers['cache-control'],
      }));
    });
    request.on('error', reject);
    request.end();
  });
}

const event = {
  eventId: 'fixture_1', timestamp: '2026-05-07T12:00:00Z',
  url: 'https://api.deepseek.com/chat/completions', method: 'POST',
  payloadSnippet: 'public test text', user: 'example@example.test', department: 'test',
  sourceHost: '127.0.0.1', bytesUp: 64, bytesDown: 64,
};

test('dashboard summary is explicitly synthetic', async () => {
  const response = await get('/api/dashboard/summary');
  assert.equal(response.status, 200);
  const body = await response.json() as {
    dataMode: string; fixtureAsOf: string; fleet: { totalEvents: number };
  };
  assert.equal(body.dataMode, 'synthetic-demo');
  assert.equal(body.fixtureAsOf, '2026-05-07T16:00:00Z');
  assert.ok(body.fleet.totalEvents > 0);
});

test('catalog and all fixture routes disclose their source boundary', async () => {
  const catalog = await get('/api/endpoints');
  assert.equal(catalog.status, 200);
  const catalogBody = await catalog.json() as {
    dataMode: string; sanctionedListMode: string; countryHandling: string;
    providers: Array<{ notes: string }>;
  };
  assert.equal(catalogBody.dataMode, 'illustrative-catalog');
  assert.equal(catalogBody.sanctionedListMode, 'fictional-sample');
  assert.equal(catalogBody.countryHandling, 'catalog-metadata-not-processing-location');
  assert.ok(catalogBody.providers.every((provider) => !/sanctioned for production|export-control concern|eu-hosted/i.test(provider.notes)));

  const incidents = await get('/api/incidents');
  const incidentList = await incidents.json() as { incidents: Array<{ incidentId: string }> };
  assert.ok(incidentList.incidents.length > 0);
  const incident = await get(`/api/incidents/${encodeURIComponent(incidentList.incidents[0].incidentId)}`);
  assert.equal((await incident.json() as { dataMode: string }).dataMode, 'synthetic-demo');
  const exposure = await get('/api/dashboard/exposure');
  assert.equal((await exposure.json() as { dataMode: string }).dataMode, 'synthetic-demo');
});

test('preview serves the API-backed synthetic fixture console', async () => {
  const response = await get('/preview');
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /SYNTHETIC FIXTURE/);
  assert.match(html, /\/preview\.js/);
});

test('local demo rejects foreign Host and selected forwarding headers before routing', async () => {
  const foreignHost = await getWithHeaders('/health', { host: 'attacker.example' });
  assert.equal(foreignHost.status, 403);
  assert.equal(foreignHost.cacheControl, 'no-store');
  assert.doesNotMatch(foreignHost.body, /uptimeSeconds/);

  for (const [header, value] of Object.entries({
    forwarded: 'for=203.0.113.7',
    'x-forwarded-for': '203.0.113.7',
    'x-forwarded-host': 'attacker.example',
  })) {
    const forwarded = await getWithHeaders('/api/dashboard/summary', { [header]: value });
    assert.equal(forwarded.status, 403, header);
  }

  const crossOrigin = await fetch(new URL('/api/analyze/payload', baseUrl), {
    method: 'POST',
    headers: { origin: 'https://attacker.example', 'content-type': 'application/json' },
    body: JSON.stringify({ payload: 'synthetic only' }),
  });
  assert.equal(crossOrigin.status, 403);

  const local = await get('/health');
  assert.equal(local.status, 200);
});

test('production runtime cannot start the unauthenticated demo', () => {
  assert.equal(canStartLocalDemo('development'), true);
  assert.equal(canStartLocalDemo('test'), true);
  assert.equal(canStartLocalDemo('production'), false);
  assert.equal(canStartLocalDemo('staging'), false);
});

test('a remote peer cannot bypass the local boundary with a forged Host', () => {
  const request = {
    headers: { host: 'localhost:3000' },
    socket: { remoteAddress: '203.0.113.7' },
  } as unknown as Request;
  assert.equal(isLocalDemoRequest(request), false);
});

test('callers cannot override the sanctioned endpoint list', async () => {
  const response = await post('/api/analyze/event', {
    event, sanctionedEndpointIds: ['deepseek-api'],
  });
  assert.equal(response.status, 400);
  const normal = await post('/api/analyze/event', { event });
  assert.equal(normal.status, 200);
  assert.equal((await normal.json() as { sanctionStatus: string }).sanctionStatus, 'unsanctioned');
});

test('payload result never returns secret fragments', async () => {
  const syntheticGitHubToken = `ghp_${'a'.repeat(36)}`;
  const response = await post('/api/analyze/payload', {
    payload: `GH_TOKEN=${syntheticGitHubToken}`,
  });
  assert.equal(response.status, 200);
  const body = await response.json() as { hits: { matchedSnippet: string }[] };
  assert.ok(body.hits.length > 0);
  assert.ok(body.hits.every((hit: { matchedSnippet: string }) => hit.matchedSnippet === '[redacted]'));
  assert.equal(JSON.stringify(body).includes(syntheticGitHubToken), false);
});

test('payload scan never reflects a caller-provided correlation ID', async () => {
  const marker = 'private-person@example.test';
  const response = await post('/api/analyze/payload', {
    payload: 'Customer SSN 123-45-6789', payloadId: marker,
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json() as { payloadId: string | null };
  assert.equal(body.payloadId, null);
  assert.doesNotMatch(JSON.stringify(body), /private-person@example\.test|123-45-6789/);
});

test('single-event assessment omits caller identifiers and payload fragments', async () => {
  const marker = 'private-person@example.test';
  const response = await post('/api/analyze/event', {
    event: {
      ...event, eventId: marker, user: marker, department: marker, sourceHost: marker,
      url: `https://api.deepseek.com/chat/completions?token=${marker}`,
      payloadSnippet: `Customer SSN 123-45-6789 for ${marker}`,
    },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json() as {
    dataMode: string; eventId?: string;
    payloadHits: { payloadId: string | null };
  };
  assert.equal(body.dataMode, 'caller-supplied-unverified');
  assert.equal(body.eventId, undefined);
  assert.equal(body.payloadHits.payloadId, null);
  assert.doesNotMatch(JSON.stringify(body), /private-person@example\.test|123-45-6789/);
});

test('bulk analysis rejects more than 50 events', async () => {
  const events = Array.from({ length: 51 }, (_, i) => ({ ...event, eventId: 'fixture_' + i }));
  const response = await post('/api/analyze/traffic', { events });
  assert.equal(response.status, 400);
});

test('caller traffic is unverified and omits user and event identifiers', async () => {
  const identifier = 'real.user@example.com';
  const response = await post('/api/analyze/traffic', {
    events: [{ ...event, eventId: `case-${identifier}`, user: identifier,
      payloadSnippet: 'Customer SSN 123-45-6789' }],
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json() as {
    dataMode: string; identifierHandling: string;
    summary: { totalEvents: number; topRiskUsers?: unknown };
    assessments: Array<{ inputIndex: number; eventId?: string; payloadHits: { payloadId: string | null } }>;
  };
  assert.equal(body.dataMode, 'caller-supplied-unverified');
  assert.equal(body.identifierHandling, 'caller-identifiers-omitted');
  assert.equal(body.summary.totalEvents, 1);
  assert.equal(body.summary.topRiskUsers, undefined);
  assert.equal(body.assessments[0].inputIndex, 0);
  assert.equal(body.assessments[0].eventId, undefined);
  assert.equal(body.assessments[0].payloadHits.payloadId, null);
  assert.doesNotMatch(JSON.stringify(body), /real\.user@example\.com/);

  const fixture = await get('/api/dashboard/summary');
  assert.equal((await fixture.json() as { dataMode: string }).dataMode, 'synthetic-demo');
  const incidents = await get('/api/incidents');
  assert.equal((await incidents.json() as { dataMode: string }).dataMode, 'synthetic-demo');
});

test('bulk assessment uses request-local department labels without exposing identifiers', async () => {
  const marker = 'private-person@example.test';
  const response = await post('/api/analyze/traffic', {
    events: [
      { ...event, eventId: `case-1-${marker}`, user: marker, department: `division-${marker}`,
        sourceHost: marker, payloadSnippet: `Customer SSN 123-45-6789 for ${marker}` },
      { ...event, eventId: `case-2-${marker}`, user: marker, department: `division-${marker}` },
      { ...event, eventId: `case-3-${marker}`, user: marker, department: 'another-private-division' },
    ],
  });
  assert.equal(response.status, 200);
  const body = await response.json() as {
    summary: { byDepartment: Record<string, number> };
    departments: Array<{ department: string; totalEvents: number; uniqueUsers: number }>;
  };
  assert.deepEqual(body.summary.byDepartment, { 'Department 1': 2, 'Department 2': 1 });
  assert.deepEqual(body.departments.map((item) => item.department).sort(), ['Department 1', 'Department 2']);
  assert.equal(body.departments.find((item) => item.department === 'Department 1')?.uniqueUsers, 1);
  assert.doesNotMatch(JSON.stringify(body), /private-person@example\.test|another-private-division|123-45-6789/);
});

test('validation and missing-incident errors do not reflect caller strings', async () => {
  const marker = 'private-person@example.test';
  const invalid = await post('/api/analyze/event', { event: { ...event, method: marker } });
  assert.equal(invalid.status, 400);
  assert.doesNotMatch(await invalid.text(), /private-person@example\.test/);
  const missing = await get(`/api/incidents/${encodeURIComponent(marker)}`);
  assert.equal(missing.status, 404);
  assert.doesNotMatch(await missing.text(), /private-person@example\.test/);
});
