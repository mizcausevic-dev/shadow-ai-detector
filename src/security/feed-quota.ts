import type { RequestHandler } from 'express';
import { performance } from 'node:perf_hooks';

const CAPACITY = 60;
const REFILL_INTERVAL_MS = 1_000;

/** A single process-local quota for the opt-in loopback feed, before JWT work. */
export function createFeedQuota(clock: () => number = () => performance.now()): RequestHandler {
  let tokens = CAPACITY;
  let lastRefill = clock();

  return (_req, res, next) => {
    const now = clock();
    const elapsed = Math.max(0, now - lastRefill);
    tokens = Math.min(CAPACITY, tokens + elapsed / REFILL_INTERVAL_MS);
    lastRefill = now;

    if (tokens < 1) {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((1 - tokens) * REFILL_INTERVAL_MS / 1_000))));
      res.status(429).json({ error: 'Feed request limit exceeded' });
      return;
    }
    tokens -= 1;
    next();
  };
}
