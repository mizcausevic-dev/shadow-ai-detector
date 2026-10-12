import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import type { Request, RequestHandler } from 'express';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const TOKEN_ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const REQUIRED_SCOPE = 'shadow:feed:analyze';

export interface FeedPrincipal {
  subject: string;
  clientId: string;
  tenantId: string;
  tokenId: string;
}

export interface FeedBoundaryConfig {
  issuer: string;
  audience: string;
  /** Pinned public Ed25519 verification keys from the selected issuer. */
  publicKeys: JSONWebKeySet;
  /** An authoritative, fail-closed token status or revocation check. */
  isTokenActive: (principal: FeedPrincipal) => Promise<boolean>;
  /** Server-owned resource registry; never read tenant ownership from the request. */
  tenantForResource: (resourceId: string) => Promise<string | null>;
  /** Server-owned grant binding the signed client_id to this exact resource. */
  isClientAllowedForResource: (principal: FeedPrincipal, resourceId: string) => Promise<boolean>;
}

export function createFeedBoundary(config: FeedBoundaryConfig): RequestHandler {
  const issuerUrl = new URL(config.issuer);
  if (issuerUrl.protocol !== 'https:' || issuerUrl.username || issuerUrl.password ||
      issuerUrl.search || issuerUrl.hash || issuerUrl.origin === 'null' ||
      typeof config.audience !== 'string' || !config.audience.trim() ||
      typeof config.isTokenActive !== 'function' ||
      typeof config.tenantForResource !== 'function' ||
      typeof config.isClientAllowedForResource !== 'function') {
    throw new Error('Feed identity configuration is incomplete.');
  }

  const keys = config.publicKeys?.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 5 ||
      keys.some((key) => key.kty !== 'OKP' || key.crv !== 'Ed25519' ||
        typeof key.x !== 'string' || typeof key.kid !== 'string' || !key.kid ||
        ('d' in key) || ('x5u' in key) ||
        (key.alg !== undefined && key.alg !== 'EdDSA') ||
        (key.use !== undefined && key.use !== 'sig')) ||
      new Set(keys.map((key) => key.kid)).size !== keys.length) {
    throw new Error('Feed verification keys must be pinned public Ed25519 keys.');
  }
  const jwks = createLocalJWKSet(config.publicKeys);
  const allowedKeyIds = new Set(keys.map((key) => key.kid));

  return (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const resourceId = req.params.resourceId;
    const authorizationHeaders = req.rawHeaders.filter((header, index) =>
      index % 2 === 0 && header.toLowerCase() === 'authorization');
    const match = typeof req.headers.authorization === 'string' &&
      req.headers.authorization.length <= 8192 &&
      BEARER.exec(req.headers.authorization);
    if (authorizationHeaders.length !== 1 || !match ||
        typeof resourceId !== 'string' || !IDENTIFIER.test(resourceId)) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    void (async () => {
      const { payload, protectedHeader } = await jwtVerify(match[1], jwks, {
        algorithms: ['EdDSA'], issuer: config.issuer, audience: config.audience,
        typ: 'at+jwt', requiredClaims: ['exp', 'iat', 'jti', 'sub', 'client_id', 'tenant_id', 'scope'],
        maxTokenAge: '5 minutes', clockTolerance: '5 seconds',
      });
      if (typeof protectedHeader.kid !== 'string' || !allowedKeyIds.has(protectedHeader.kid) ||
          payload.aud !== config.audience ||
          typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 200 ||
          typeof payload.client_id !== 'string' || !IDENTIFIER.test(payload.client_id) ||
          typeof payload.jti !== 'string' || !TOKEN_ID.test(payload.jti) ||
          typeof payload.tenant_id !== 'string' || !IDENTIFIER.test(payload.tenant_id) ||
          typeof payload.scope !== 'string' ||
          !payload.scope.split(' ').includes(REQUIRED_SCOPE)) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      const principal: FeedPrincipal = {
        subject: payload.sub, clientId: payload.client_id,
        tenantId: payload.tenant_id, tokenId: payload.jti,
      };
      // Status errors also deny the request. A test stub is not a production revocation source.
      if (!(await config.isTokenActive(principal))) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      if ((await config.tenantForResource(resourceId)) !== principal.tenantId) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
      if (!(await config.isClientAllowedForResource(principal, resourceId))) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
      next();
    })().catch(() => {
      if (!res.headersSent) res.status(401).json({ error: 'Unauthorized' });
    });
  };
}
