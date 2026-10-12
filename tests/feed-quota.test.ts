import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { createFeedQuota } from '../src/security/feed-quota';

test('feed quota refills exactly over a monotonic clock and caps its burst', async () => {
  let nowMs = 0;
  const app = express();
  app.use(createFeedQuota(() => nowMs));
  app.get('/probe', (_req, res) => res.sendStatus(204));
  const server = app.listen(0, '127.0.0.1');
  try {
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/probe`;
    const status = async () => (await fetch(url)).status;

    for (let index = 0; index < 60; index += 1) assert.equal(await status(), 204);
    assert.equal(await status(), 429);
    nowMs = 999;
    assert.equal(await status(), 429);
    nowMs = 1_000;
    assert.equal(await status(), 204);
    assert.equal(await status(), 429);

    nowMs = 61_000;
    for (let index = 0; index < 60; index += 1) assert.equal(await status(), 204);
    assert.equal(await status(), 429);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
