import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { app } from '../src/index';

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

test('preview serves the API-backed synthetic fixture console', async () => {
  const response = await get('/preview');
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /SYNTHETIC FIXTURE/);
  assert.match(html, /\/preview\.js/);
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
  const response = await post('/api/analyze/payload', {
    payload: 'GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
  });
  assert.equal(response.status, 200);
  const body = await response.json() as { hits: { matchedSnippet: string }[] };
  assert.ok(body.hits.length > 0);
  assert.ok(body.hits.every((hit: { matchedSnippet: string }) => hit.matchedSnippet === '[redacted]'));
  assert.doesNotMatch(JSON.stringify(body), /aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/);
});

test('bulk analysis rejects more than 50 events', async () => {
  const events = Array.from({ length: 51 }, (_, i) => ({ ...event, eventId: 'fixture_' + i }));
  const response = await post('/api/analyze/traffic', { events });
  assert.equal(response.status, 400);
});
