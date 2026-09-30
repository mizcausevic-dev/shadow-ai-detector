import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import request from 'supertest';
import { app } from '../src/index';

let server: Server;
before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
});
after(() => server.close());

const event = {
  eventId: 'fixture_1', timestamp: '2026-05-07T12:00:00Z',
  url: 'https://api.deepseek.com/chat/completions', method: 'POST',
  payloadSnippet: 'public test text', user: 'example@example.test', department: 'test',
  sourceHost: '127.0.0.1', bytesUp: 64, bytesDown: 64,
};

test('dashboard summary is explicitly synthetic', async () => {
  const response = await request(server).get('/api/dashboard/summary');
  assert.equal(response.status, 200);
  assert.equal(response.body.dataMode, 'synthetic-demo');
  assert.equal(response.body.fixtureAsOf, '2026-05-07T16:00:00Z');
  assert.ok(response.body.fleet.totalEvents > 0);
});

test('preview serves the API-backed synthetic fixture console', async () => {
  const response = await request(server).get('/preview');
  assert.equal(response.status, 200);
  assert.match(response.text, /SYNTHETIC FIXTURE/);
  assert.match(response.text, /\/preview\.js/);
});

test('callers cannot override the sanctioned endpoint list', async () => {
  const response = await request(server).post('/api/analyze/event').send({
    event, sanctionedEndpointIds: ['deepseek-api'],
  });
  assert.equal(response.status, 400);
  const normal = await request(server).post('/api/analyze/event').send({ event });
  assert.equal(normal.status, 200);
  assert.equal(normal.body.sanctionStatus, 'unsanctioned');
});

test('payload result never returns secret fragments', async () => {
  const response = await request(server).post('/api/analyze/payload').send({
    payload: 'GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
  });
  assert.equal(response.status, 200);
  assert.ok(response.body.hits.length > 0);
  assert.ok(response.body.hits.every((hit: { matchedSnippet: string }) => hit.matchedSnippet === '[redacted]'));
  assert.doesNotMatch(JSON.stringify(response.body), /aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/);
});

test('bulk analysis rejects more than 50 events', async () => {
  const events = Array.from({ length: 51 }, (_, i) => ({ ...event, eventId: 'fixture_' + i }));
  const response = await request(server).post('/api/analyze/traffic').send({ events });
  assert.equal(response.status, 400);
});
