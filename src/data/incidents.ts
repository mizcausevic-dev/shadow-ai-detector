// Fictional incident fixtures for UI and API demonstrations. No case is real.

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
    title: 'INTERNAL ONLY marker in fictional DeepSeek traffic',
    user: 'grace.intern@corp.com',
    department: 'product',
    endpointId: 'deepseek-api',
    signalCount: 4,
    recommendedAction: 'Validate the sample signal; consult security and legal before any policy action.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_002',
    openedAt: '2026-05-07T11:05:11Z',
    severity: 'critical',
    status: 'investigating',
    title: 'Fictional Yandex GPT call flagged for regional review',
    user: 'henry.marketing@corp.com',
    department: 'marketing',
    endpointId: 'yandex-gpt',
    signalCount: 3,
    recommendedAction: 'Validate endpoint and applicable rules before any legal or block decision.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_003',
    openedAt: '2026-05-07T09:33:48Z',
    severity: 'high',
    status: 'open',
    title: 'Fictional M&A marker pattern in claude.ai example',
    user: 'dave.exec@corp.com',
    department: 'executive',
    endpointId: 'claude-ai-web',
    signalCount: 2,
    recommendedAction: 'Verify the pattern and policy context before deciding whether session review is warranted.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_004',
    openedAt: '2026-05-07T09:11:05Z',
    severity: 'high',
    status: 'investigating',
    title: 'Fictional PII pattern in chatgpt.com example',
    user: 'carol.sales@corp.com',
    department: 'sales',
    endpointId: 'chatgpt-web',
    signalCount: 4,
    recommendedAction: 'Validate the sample indicators and consult privacy counsel before any notification decision.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_07_005',
    openedAt: '2026-05-07T10:02:33Z',
    severity: 'high',
    status: 'mitigated',
    title: 'Fictional AWS credential pattern in OpenAI example',
    user: 'eve.dev@corp.com',
    department: 'engineering',
    endpointId: 'openai-api',
    signalCount: 3,
    recommendedAction: 'For a real finding, verify scope and rotate credentials through the approved incident process.',
    ownerTeam: 'security-ops',
  },
  {
    incidentId: 'inc_2026_05_06_012',
    openedAt: '2026-05-06T14:22:11Z',
    severity: 'medium',
    status: 'open',
    title: 'Fictional Together AI usage outside sample allowlist',
    user: 'frank.dev@corp.com',
    department: 'engineering',
    endpointId: 'together-api',
    signalCount: 2,
    recommendedAction: 'Review the example against an approved-tools policy before any allowlist change.',
    ownerTeam: 'platform-eng',
  },
];
