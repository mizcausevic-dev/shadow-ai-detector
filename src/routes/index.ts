import { Router } from 'express';
import {
  ClassifyEndpointSchema,
  ScanPayloadSchema,
  AnalyzeTrafficSchema,
  AssessSingleEventSchema,
} from '../schemas/validation-schemas';
import { classifyEndpoint, listKnownEndpoints } from '../governance/endpoint-classifier';
import { scanPayload, type PayloadScanResult } from '../governance/payload-scanner';
import { assessEvent, assessFleet, type RiskAssessment, type TrafficEvent } from '../governance/risk-scorer';
import { rollupByDepartment } from '../governance/department-rollup';
import { SANCTIONED_ENDPOINT_IDS, PROVIDER_METADATA } from '../data/endpoints';
import { TRAFFIC_EVENTS } from '../data/traffic';
import { INCIDENTS } from '../data/incidents';

// Caller strings may be names, emails, hostnames, or tokens. Keep grouping
// within a request, but pass only request-local labels to the scoring helpers.
function labelEvents(events: TrafficEvent[]): TrafficEvent[] {
  const departments = new Map<string, string>();
  const users = new Map<string, string>();
  const label = (labels: Map<string, string>, value: string, kind: string): string => {
    let result = labels.get(value);
    if (!result) {
      result = `${kind} ${labels.size + 1}`;
      labels.set(value, result);
    }
    return result;
  };
  return events.map((event, index) => ({
    ...event,
    eventId: `Input ${index + 1}`,
    user: label(users, event.user, 'User'),
    department: label(departments, event.department, 'Department'),
    sourceHost: '[omitted]',
  }));
}

// Explicitly allowlist response fields so a later scorer field cannot expose
// raw caller data through these analysis endpoints.
function publicPayloadHits(result: PayloadScanResult) {
  return {
    payloadId: null,
    hits: result.hits.map((hit) => ({
      patternName: hit.patternName,
      category: hit.category,
      severity: hit.severity,
      description: hit.description,
      matchedSnippet: '[redacted]',
    })),
    highestSeverity: result.highestSeverity,
    shouldBlock: result.shouldBlock,
    byCategory: result.byCategory,
  };
}

function publicAssessment(assessment: RiskAssessment, inputIndex: number) {
  return {
    inputIndex,
    matched: assessment.matched,
    endpointId: assessment.endpointId,
    provider: assessment.provider,
    sanctionStatus: assessment.sanctionStatus,
    riskScore: assessment.riskScore,
    riskTier: assessment.riskTier,
    signals: assessment.signals,
    payloadHits: publicPayloadHits(assessment.payloadHits),
    recommendedAction: assessment.recommendedAction,
  };
}

export const endpointsRouter = Router();

endpointsRouter.get('/', (_req, res) => {
  const endpoints = listKnownEndpoints();
  res.json({
    catalogSize: endpoints.length,
    sanctionedCount: SANCTIONED_ENDPOINT_IDS.size,
    endpoints,
    providers: PROVIDER_METADATA,
  });
});

endpointsRouter.post('/classify', (req, res) => {
  const parsed = ClassifyEndpointSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  res.json(classifyEndpoint(parsed.data.url));
});

export const analyzeRouter = Router();

analyzeRouter.use((_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

analyzeRouter.post('/payload', (req, res) => {
  const parsed = ScanPayloadSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  res.json({
    dataMode: 'caller-supplied-unverified',
    identifierHandling: 'caller-identifiers-omitted',
    ...publicPayloadHits(scanPayload(parsed.data.payload)),
  });
});

analyzeRouter.post('/event', (req, res) => {
  const parsed = AssessSingleEventSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  const [event] = labelEvents([parsed.data.event]);
  const assessment = assessEvent(event, SANCTIONED_ENDPOINT_IDS);
  res.json({
    dataMode: 'caller-supplied-unverified',
    identifierHandling: 'caller-identifiers-omitted',
    ...publicAssessment(assessment, 0),
  });
});

analyzeRouter.post('/traffic', (req, res) => {
  const parsed = AnalyzeTrafficSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  const events = labelEvents(parsed.data.events);
  const fleet = assessFleet(events, SANCTIONED_ENDPOINT_IDS);
  const departments = rollupByDepartment(events, fleet.assessments);
  const { totalEvents, llmEvents, byTier, byProvider, byDepartment, unsanctionedEvents } = fleet.summary;
  const assessments = fleet.assessments.map(publicAssessment);
  res.json({
    dataMode: 'caller-supplied-unverified',
    identifierHandling: 'caller-identifiers-omitted',
    departmentLabels: 'request-local',
    summary: { totalEvents, llmEvents, byTier, byProvider, byDepartment, unsanctionedEvents },
    departments,
    assessments,
  });
});

export const incidentsRouter = Router();

incidentsRouter.get('/', (req, res) => {
  const status = (req.query.status as string | undefined)?.toLowerCase();
  const severity = (req.query.severity as string | undefined)?.toLowerCase();
  let filtered = INCIDENTS;
  if (status) filtered = filtered.filter((i) => i.status === status);
  if (severity) filtered = filtered.filter((i) => i.severity === severity);
  res.json({ dataMode: 'synthetic-demo', count: filtered.length, incidents: filtered });
});

incidentsRouter.get('/:id', (req, res) => {
  const i = INCIDENTS.find((x) => x.incidentId === req.params.id);
  if (!i) { res.status(404).json({ error: 'Incident not found' }); return; }
  res.json(i);
});

export const dashboardRouter = Router();

dashboardRouter.get('/summary', (_req, res) => {
  // Run the demo dataset through the risk + dept rollup once
  const fleet = assessFleet(TRAFFIC_EVENTS, SANCTIONED_ENDPOINT_IDS);
  const departments = rollupByDepartment(TRAFFIC_EVENTS, fleet.assessments);
  const openIncidents = INCIDENTS.filter((i) => i.status === 'open' || i.status === 'investigating');

  res.json({
    dataMode: 'synthetic-demo',
    fixtureAsOf: '2026-05-07T16:00:00Z',
    fleet: fleet.summary,
    departments,
    openIncidents: openIncidents.length,
    criticalIncidents: openIncidents.filter((i) => i.severity === 'critical').length,
    sanctioned: {
      endpointIds: Array.from(SANCTIONED_ENDPOINT_IDS),
      catalogSize: listKnownEndpoints().length,
    },
  });
});

dashboardRouter.get('/exposure', (_req, res) => {
  const fleet = assessFleet(TRAFFIC_EVENTS, SANCTIONED_ENDPOINT_IDS);
  const departments = rollupByDepartment(TRAFFIC_EVENTS, fleet.assessments);
  res.json({ departments });
});
