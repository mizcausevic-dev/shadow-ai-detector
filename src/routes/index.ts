import { Router } from 'express';
import {
  ClassifyEndpointSchema,
  ScanPayloadSchema,
  AnalyzeTrafficSchema,
  AssessSingleEventSchema,
} from '../schemas/validation-schemas';
import { classifyEndpoint, listKnownEndpoints } from '../governance/endpoint-classifier';
import { scanPayload } from '../governance/payload-scanner';
import { assessEvent, assessFleet } from '../governance/risk-scorer';
import { rollupByDepartment } from '../governance/department-rollup';
import { SANCTIONED_ENDPOINT_IDS, PROVIDER_METADATA } from '../data/endpoints';
import { TRAFFIC_EVENTS } from '../data/traffic';
import { INCIDENTS } from '../data/incidents';

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
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload', details: parsed.error.issues }); return; }
  res.json(classifyEndpoint(parsed.data.url));
});

export const analyzeRouter = Router();

analyzeRouter.post('/payload', (req, res) => {
  const parsed = ScanPayloadSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload', details: parsed.error.issues }); return; }
  res.json(scanPayload(parsed.data.payload, parsed.data.payloadId ?? null));
});

analyzeRouter.post('/event', (req, res) => {
  const parsed = AssessSingleEventSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload', details: parsed.error.issues }); return; }
  const sanctioned = new Set<string>(parsed.data.sanctionedEndpointIds ?? Array.from(SANCTIONED_ENDPOINT_IDS));
  res.json(assessEvent(parsed.data.event, sanctioned));
});

analyzeRouter.post('/traffic', (req, res) => {
  const parsed = AnalyzeTrafficSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload', details: parsed.error.issues }); return; }
  const sanctioned = new Set<string>(parsed.data.sanctionedEndpointIds ?? Array.from(SANCTIONED_ENDPOINT_IDS));
  const fleet = assessFleet(parsed.data.events, sanctioned);
  const departments = rollupByDepartment(parsed.data.events, fleet.assessments);
  res.json({ summary: fleet.summary, departments, assessments: fleet.assessments });
});

export const incidentsRouter = Router();

incidentsRouter.get('/', (req, res) => {
  const status = (req.query.status as string | undefined)?.toLowerCase();
  const severity = (req.query.severity as string | undefined)?.toLowerCase();
  let filtered = INCIDENTS;
  if (status) filtered = filtered.filter((i) => i.status === status);
  if (severity) filtered = filtered.filter((i) => i.severity === severity);
  res.json({ count: filtered.length, incidents: filtered });
});

incidentsRouter.get('/:id', (req, res) => {
  const i = INCIDENTS.find((x) => x.incidentId === req.params.id);
  if (!i) { res.status(404).json({ error: `Incident ${req.params.id} not found.` }); return; }
  res.json(i);
});

export const dashboardRouter = Router();

dashboardRouter.get('/summary', (_req, res) => {
  // Run the demo dataset through the risk + dept rollup once
  const fleet = assessFleet(TRAFFIC_EVENTS, SANCTIONED_ENDPOINT_IDS);
  const departments = rollupByDepartment(TRAFFIC_EVENTS, fleet.assessments);
  const openIncidents = INCIDENTS.filter((i) => i.status === 'open' || i.status === 'investigating');

  res.json({
    capturedAt: new Date().toISOString(),
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
