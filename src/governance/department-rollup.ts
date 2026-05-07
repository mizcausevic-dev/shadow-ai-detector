// Department-level shadow-AI exposure rollup. The unit a CISO actually
// briefs to a board: "which departments are leaking, what providers are
// they using, what's the concentration of high-risk events per department."

import type { TrafficEvent, RiskAssessment, RiskTier } from './risk-scorer';

export interface DepartmentExposure {
  department: string;
  totalEvents: number;
  llmEvents: number;
  uniqueUsers: number;
  uniqueProviders: number;
  byTier: Record<RiskTier, number>;
  topProvider: string | null;
  unsanctionedRate: number; // % of LLM events that were unsanctioned
  exposureScore: number; // 0-100 composite for ranking
  recommendedAction: string;
}

function computeExposureScore(d: Omit<DepartmentExposure, 'exposureScore' | 'recommendedAction'>): number {
  if (d.llmEvents === 0) return 0;
  // Weight criticals heavily, highs moderately, elevated lightly
  const tierWeight = d.byTier.critical * 30 + d.byTier.high * 15 + d.byTier.elevated * 5;
  const sanctionPenalty = d.unsanctionedRate * 0.4; // 0-40 contribution
  const tierShare = (tierWeight / d.llmEvents) * 2; // bounded by raw counts/events ratio
  const raw = sanctionPenalty + tierShare;
  return Math.max(0, Math.min(100, Math.round(raw * 100) / 100));
}

export function rollupByDepartment(
  events: TrafficEvent[],
  assessments: RiskAssessment[]
): DepartmentExposure[] {
  if (events.length !== assessments.length) {
    throw new Error('Events and assessments must align 1:1.');
  }

  const buckets = new Map<string, {
    department: string;
    totalEvents: number;
    llmEvents: number;
    users: Set<string>;
    providers: Set<string>;
    providerCounts: Map<string, number>;
    byTier: Record<RiskTier, number>;
    unsanctioned: number;
  }>();

  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const a = assessments[i];
    const cur = buckets.get(e.department) || {
      department: e.department,
      totalEvents: 0,
      llmEvents: 0,
      users: new Set<string>(),
      providers: new Set<string>(),
      providerCounts: new Map<string, number>(),
      byTier: { minimal: 0, elevated: 0, high: 0, critical: 0 },
      unsanctioned: 0,
    };
    cur.totalEvents++;
    if (a.matched) {
      cur.llmEvents++;
      cur.users.add(e.user);
      if (a.provider) {
        cur.providers.add(a.provider);
        cur.providerCounts.set(a.provider, (cur.providerCounts.get(a.provider) || 0) + 1);
      }
      cur.byTier[a.riskTier]++;
      if (a.sanctionStatus === 'unsanctioned') cur.unsanctioned++;
    }
    buckets.set(e.department, cur);
  }

  const result: DepartmentExposure[] = [];
  for (const b of buckets.values()) {
    let topProvider: string | null = null;
    let topCount = 0;
    for (const [p, c] of b.providerCounts.entries()) {
      if (c > topCount) { topProvider = p; topCount = c; }
    }
    const unsanctionedRate = b.llmEvents === 0 ? 0 : Math.round((b.unsanctioned / b.llmEvents) * 1000) / 10;

    const partial = {
      department: b.department,
      totalEvents: b.totalEvents,
      llmEvents: b.llmEvents,
      uniqueUsers: b.users.size,
      uniqueProviders: b.providers.size,
      byTier: b.byTier,
      topProvider,
      unsanctionedRate,
    };
    const exposureScore = computeExposureScore(partial);

    let recommendedAction: string;
    if (exposureScore >= 60) {
      recommendedAction = 'Escalate to dept head; require all-hands AI usage briefing within 48h.';
    } else if (exposureScore >= 30) {
      recommendedAction = 'Schedule dept-level shadow-AI review; provision sanctioned alternatives.';
    } else if (exposureScore > 0) {
      recommendedAction = 'Monitor weekly; communicate sanctioned-tools list to dept.';
    } else {
      recommendedAction = 'No action; department compliant.';
    }

    result.push({ ...partial, exposureScore, recommendedAction });
  }

  return result.sort((a, b) => b.exposureScore - a.exposureScore);
}
