import express from 'express';
import helmet from 'helmet';
import { readFileSync } from 'fs';
import path from 'path';
import { env } from './config/env';
import { isLocalDemoRequest } from './config/local-boundary';
import { createFeedBoundary, type FeedBoundaryConfig } from './security/feed-boundary';
import {
  endpointsRouter,
  analyzeRouter,
  incidentsRouter,
  dashboardRouter,
} from './routes/index';

const previewHtml = readFileSync(path.join(__dirname, '..', 'dashboard-preview', 'index.html'), 'utf8');
const previewScript = readFileSync(path.join(__dirname, '..', 'dashboard-preview', 'preview.js'), 'utf8');

/** The normal runtime passes no feed configuration and cannot serve the feed path. */
export function createApp(feedBoundary?: FeedBoundaryConfig): express.Express {
  const app = express();
  app.disable('x-powered-by');
  const startedAt = Date.now();

  app.use(helmet());
  app.use((req, res, next) => {
    if (!isLocalDemoRequest(req)) {
      res.setHeader('Cache-Control', 'no-store');
      res.status(403).json({ error: 'Local synthetic demo only' });
      return;
    }
    next();
  });
  // Authorization runs before body parsing or analysis. The default app denies
  // the route even on loopback; test-only injection exercises the candidate gate.
  app.use('/api/feed/:resourceId/analyze',
    feedBoundary ? createFeedBoundary(feedBoundary) : (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.status(404).json({ error: 'Not found' });
    },
    express.json({ limit: '256kb' }),
    analyzeRouter);
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'shadow-ai-detector',
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      nodeEnv: env.nodeEnv,
    });
  });

  if (!feedBoundary) {
    // A local fixture API. No request URL or payload is logged; both may contain
    // sensitive material when callers exercise the scanner.
    app.use(express.json({ limit: '256kb' }));
    app.get('/preview', (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.type('html').send(previewHtml);
    });
    app.get('/preview.js', (_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.type('js').send(previewScript);
    });
    app.use('/api/endpoints', endpointsRouter);
    app.use('/api/analyze', analyzeRouter);
    app.use('/api/incidents', incidentsRouter);
    app.use('/api/dashboard', dashboardRouter);
  }

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const type = typeof err === 'object' && err !== null && 'type' in err ? String(err.type) : '';
    if (type === 'entity.too.large') { res.status(413).json({ error: 'Request body too large' }); return; }
    if (type === 'entity.parse.failed') { res.status(400).json({ error: 'Invalid JSON' }); return; }
    res.status(500).json({ error: 'Internal error' });
  });

  return app;
}

export const app = createApp();

if (require.main === module) {
  app.listen(env.port, '127.0.0.1', () => {
    // eslint-disable-next-line no-console
    console.log(`shadow-ai-detector listening on :${env.port}`);
  });
}
