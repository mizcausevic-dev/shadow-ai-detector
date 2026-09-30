// Composite shadow-AI risk scoring. Combines endpoint classification,
// payload sensitivity, user identity context, and volume signals into a
// illustrative triage score per traffic event. No enforcement occurs.

import { classifyEndpoint, sanctionStatus, type SanctionStatus } from './endpoint-classifier';
import { scanPayload } from './payload-scanner';

export interface TrafficEvent {
  eventId: string;
  timestamp: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  payloadSnippet: string;
  user: string;
  department: string;
  sourceHost: string;
  bytesUp: number;
  bytesDown: number;
}

export type RiskTier = 'minimal' | 'elevated' | 'high' | 'critical';

export interface RiskAssessment {
  eventId: string;
  matched: boolean;
  endpointId: string | null;
  provider: string | null;
  sanctionStatus: SanctionStatus;
  riskScore: number; // 0-100
  riskTier: RiskTier;
  signals: string[];
  payloadHits: ReturnType<typeof scanPayload>;
  recommendedAction: string;
}

const SANCTION_PENALTY: Record<SanctionStatus, number> = {
  sanctioned: 0,
  unsanctioned: 35,
  unknown: 25,
};

const ENDPOINT_RISK_WEIGHT: Record<'low' | 'medium' | 'high' | 'critical', number> = {
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
};

const SEVERITY_PENALTY = {
  critical: 35,
  high: 20,
  medium: 10,
  low: 3,
} as const;

export function assessEvent(event: TrafficEvent, sanctionedIds: Set<string>): RiskAssessment {
  const classification = classifyEndpoint(event.url);
  const sanction = sanctionStatus(classification.endpointId, { sanctionedEndpointIds: sanctionedIds });
  const payloadResult = scanPayload(event.payloadSnippet, event.eventId);

  let score = 0;
  const signals: string[] = [];

  if (!classification.matched) {
    // Unknown LLM endpoint reaching a non-cataloged host is still concerning if
    // sensitive payload signals are present, but we don't auto-flag pure traffic.
    signals.push('Endpoint not in LLM catalog; classified as non-LLM traffic.');
    if (payloadResult.hits.length === 0) {
      return {
        eventId: event.eventId,
        matched: false,
        endpointId: null,
        provider: null,
        sanctionStatus: 'unknown',
        riskScore: 0,
        riskTier: 'minimal',
        signals,
        payloadHits: payloadResult,
        recommendedAction: 'No action; not LLM traffic.',
      };
    }
  } else {
    // Endpoint risk band
    const band = classification.defaultRisk ?? 'medium';
    score += ENDPOINT_RISK_WEIGHT[band];
    signals.push(`Endpoint ${classification.endpointId} classified as ${band} default risk.`);

    // Sanction posture
    score += SANCTION_PENALTY[sanction];
    if (sanction === 'unsanctioned') signals.push('Endpoint not on the sample allowlist.');
    if (sanction === 'unknown') signals.push('Sample allowlist status unknown.');
    if (classification.notes) signals.push(classification.notes);
    if (classification.sourceCountry && ['CN', 'RU'].includes(classification.sourceCountry)) {
      signals.push(`Catalog country is ${classification.sourceCountry}; verify actual processing location and applicable transfer rules.`);
      score += 15;
    }
  }

  // Payload sensitivity
  for (const hit of payloadResult.hits) {
    score += SEVERITY_PENALTY[hit.severity];
    signals.push(`${hit.category} pattern detected: ${hit.patternName} (${hit.severity}).`);
  }
  if (payloadResult.shouldBlock) {
    signals.push('Payload contains a pattern requiring human review before any block decision.');
  }

  // Volume signal — large uploads to LLM endpoints are noteworthy
  if (event.bytesUp > 256 * 1024) {
    signals.push(`Upload size ${(event.bytesUp / 1024).toFixed(0)}KB exceeds 256KB threshold.`);
    score += 10;
  }

  // Cap and bucket
  score = Math.max(0, Math.min(100, score));

  let riskTier: RiskTier;
  let recommendedAction: string;
  if (score >= 75) {
    riskTier = 'critical';
    recommendedAction = 'Review for possible egress block and escalation; validate the finding and retention basis first.';
  } else if (score >= 50) {
    riskTier = 'high';
    recommendedAction = 'Review whether session quarantine or department follow-up is warranted.';
  } else if (score >= 25) {
    riskTier = 'elevated';
    recommendedAction = 'Review against the approved-tools register and local policy.';
  } else {
    riskTier = 'minimal';
    recommendedAction = 'No pattern flagged in this sample; continue normal monitoring.';
  }

  return {
    eventId: event.eventId,
    matched: classification.matched,
    endpointId: classification.endpointId,
    provider: classification.provider,
    sanctionStatus: sanction,
    riskScore: score,
    riskTier,
    signals,
    payloadHits: payloadResult,
    recommendedAction,
  };
}

export interface FleetAssessment {
  totalEvents: number;
  llmEvents: number;
  byTier: Record<RiskTier, number>;
  byProvider: Record<string, number>;
  byDepartment: Record<string, number>;
  topRiskUsers: Array<{ user: string; department: string; eventCount: number; maxScore: number }>;
  unsanctionedEvents: number;
}

export function assessFleet(events: TrafficEvent[], sanctionedIds: Set<string>): {
  summary: FleetAssessment;
  assessments: RiskAssessment[];
} {
  const assessments = events.map((e) => assessEvent(e, sanctionedIds));
  const llmAssessments = assessments.filter((a) => a.matched);

  const byTier: Record<RiskTier, number> = { minimal: 0, elevated: 0, high: 0, critical: 0 };
  const byProvider: Record<string, number> = Object.create(null);
  const byDepartment: Record<string, number> = Object.create(null);
  const userStats = new Map<string, { user: string; department: string; eventCount: number; maxScore: number }>();
  let unsanctionedEvents = 0;

  for (let i = 0; i < assessments.length; i++) {
    const a = assessments[i];
    const e = events[i];
    byTier[a.riskTier]++;
    if (a.provider) {
      byProvider[a.provider] = (byProvider[a.provider] || 0) + 1;
    }
    if (a.matched) {
      byDepartment[e.department] = (byDepartment[e.department] || 0) + 1;
      if (a.sanctionStatus === 'unsanctioned') unsanctionedEvents++;
      const cur = userStats.get(e.user) || { user: e.user, department: e.department, eventCount: 0, maxScore: 0 };
      cur.eventCount++;
      if (a.riskScore > cur.maxScore) cur.maxScore = a.riskScore;
      userStats.set(e.user, cur);
    }
  }

  const topRiskUsers = Array.from(userStats.values())
    .sort((a, b) => b.maxScore - a.maxScore || b.eventCount - a.eventCount)
    .slice(0, 10);

  return {
    summary: {
      totalEvents: events.length,
      llmEvents: llmAssessments.length,
      byTier,
      byProvider,
      byDepartment,
      topRiskUsers,
      unsanctionedEvents,
    },
    assessments,
  };
}
