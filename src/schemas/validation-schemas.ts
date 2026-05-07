import { z } from 'zod';

export const TrafficEventSchema = z.object({
  eventId: z.string().min(1),
  timestamp: z.string().min(1),
  url: z.string().min(1),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  payloadSnippet: z.string(),
  user: z.string().min(1),
  department: z.string().min(1),
  sourceHost: z.string().min(1),
  bytesUp: z.number().min(0),
  bytesDown: z.number().min(0),
});

export const ClassifyEndpointSchema = z.object({
  url: z.string().min(1),
});

export const ScanPayloadSchema = z.object({
  payload: z.string(),
  payloadId: z.string().optional(),
});

export const AnalyzeTrafficSchema = z.object({
  events: z.array(TrafficEventSchema).min(1),
  sanctionedEndpointIds: z.array(z.string()).optional(),
});

export const AssessSingleEventSchema = z.object({
  event: TrafficEventSchema,
  sanctionedEndpointIds: z.array(z.string()).optional(),
});
