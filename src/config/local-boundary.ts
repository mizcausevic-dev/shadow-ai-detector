import type { Request } from 'express';

const LOOPBACK_PEERS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$/i;

/** This demo accepts only direct loopback HTTP, even if an embedder changes listen(). */
export function isLocalDemoRequest(req: Request): boolean {
  const host = req.headers.host;
  if (!host || !LOCAL_HOST.test(host) || !LOOPBACK_PEERS.has(req.socket.remoteAddress ?? '')) return false;
  if (req.headers.forwarded || req.headers['x-forwarded-for'] || req.headers['x-forwarded-host']) return false;

  const origin = req.headers.origin;
  if (origin && origin !== `http://${host}`) return false;
  return true;
}

export function canStartLocalDemo(nodeEnv: string): boolean {
  return nodeEnv === 'development' || nodeEnv === 'test';
}
