import type { Request } from 'express';

const LOOPBACK_PEERS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1)(?::([1-9]\d{0,4}))?$/i;

/** This demo accepts only direct loopback HTTP, even if an embedder changes listen(). */
export function isLocalDemoRequest(req: Request): boolean {
  const host = req.headers.host;
  const hostMatch = LOCAL_HOST.exec(host ?? '');
  if (!hostMatch || (hostMatch[1] && Number(hostMatch[1]) > 65535) ||
      !LOOPBACK_PEERS.has(req.socket.remoteAddress ?? '')) return false;
  if (req.headers.forwarded || req.headers['x-forwarded-for'] || req.headers['x-forwarded-host'] ||
      req.headers['x-forwarded-proto'] || req.headers.via) return false;

  const origin = req.headers.origin;
  if (origin && origin !== `http://${host}`) return false;
  return true;
}

export function canStartLocalDemo(nodeEnv: string | undefined, localFixtureOptIn: boolean): boolean {
  return localFixtureOptIn && (nodeEnv === 'development' || nodeEnv === 'test');
}
