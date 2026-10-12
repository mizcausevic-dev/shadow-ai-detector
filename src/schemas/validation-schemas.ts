import { z } from 'zod';

export const TrafficEventSchema = z.object({
  eventId: z.string().min(1).max(100),
  timestamp: z.string().datetime(),
  url: z.string().min(1).max(2048),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  payloadSnippet: z.string().max(16_384),
  user: z.string().min(1).max(200),
  department: z.string().min(1).max(100),
  sourceHost: z.string().min(1).max(255),
  bytesUp: z.number().int().min(0).max(1_000_000_000),
  bytesDown: z.number().int().min(0).max(1_000_000_000),
});

export const ClassifyEndpointSchema = z.object({
  url: z.string().min(1).max(2048),
});

export const ScanPayloadSchema = z.object({
  payload: z.string().max(16_384),
  payloadId: z.string().max(100).optional(),
});

export const AnalyzeTrafficSchema = z.object({
  events: z.array(TrafficEventSchema).min(1).max(50),
}).strict();

export const AssessSingleEventSchema = z.object({
  event: TrafficEventSchema,
}).strict();
