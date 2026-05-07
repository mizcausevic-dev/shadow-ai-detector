// Active shadow-AI incidents currently under review by the security team.

export type IncidentStatus = 'open' | 'investigating' | 'mitigated' | 'closed';
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface Incident {
  incidentId: string;
  openedAt: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  title: string;
  user: string;
  department: string;
  endpointId: string;
  signalCount: number;
  recommendedAction: string;
  ownerTeam: string;
}

export const INCIDENTS: Incident[] = [
  {
    incidentId: 'inc_2026_05_07_001',
    openedAt: '2026-05-07T11:02:30Z',
    severity: 'critical',
    status: 'investigating',
    title: 'INTERNAL ONLY material sent to foreign-hosted LLM (DeepSeek)',
    user: 'grace.intern@corp.com',
    department: 'product',
    endpointId: 'deepseek-api',
    signalCount: 4,
    recommendedAction: 'Block egress; escalate to legal; review intern-onboarding security training.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_002',
    openedAt: '2026-05-07T11:05:11Z',
    severity: 'critical',
    status: 'investigating',
    title: 'Yandex GPT call from marketing dept (sanctions concern)',
    user: 'henry.marketing@corp.com',
    department: 'marketing',
    endpointId: 'yandex-gpt',
    signalCount: 3,
    recommendedAction: 'Block egress at firewall; legal escalation for sanctions review.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_003',
    openedAt: '2026-05-07T09:33:48Z',
    severity: 'high',
    status: 'open',
    title: 'M&A codename leaked to claude.ai consumer interface',
    user: 'dave.exec@corp.com',
    department: 'executive',
    endpointId: 'claude-ai-web',
    signalCount: 2,
    recommendedAction: 'Quarantine session; require justification; consider provisioning sanctioned API access for executive team.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_004',
    openedAt: '2026-05-07T09:11:05Z',
    severity: 'high',
    status: 'investigating',
    title: 'Customer PII (SSN + DOB) sent to chatgpt.com',
    user: 'carol.sales@corp.com',
    department: 'sales',
    endpointId: 'chatgpt-web',
    signalCount: 4,
    recommendedAction: 'Quarantine; alert sales mgr; refresher training; assess GDPR/CCPA implications.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_005',
    openedAt: '2026-05-07T10:02:33Z',
    severity: 'high',
    status: 'mitigated',
    title: 'AWS credential leaked in OpenAI prompt (rotated)',
    user: 'eve.dev@corp.com',
    department: 'engineering',
    endpointId: 'openai-api',
    signalCount: 3,
    recommendedAction: 'Credential rotated; audit-log preserved; user counseled.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_06_012',
    openedAt: '2026-05-06T14:22:11Z',
    severity: 'medium',
    status: 'open',
    title: 'Repeated unsanctioned Together AI usage (engineering)',
    user: 'frank.dev@corp.com',
    department: 'engineering',
    endpointId: 'together-api',
    signalCount: 2,
    recommendedAction: 'Add to weekly-review queue; consider sanctioning if pattern continues.',
    ownerTeam: 'platform-eng',
  },
];
