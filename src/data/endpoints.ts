// Fictional organization's sample allowlist. This is not a real provider
// approval or a statement about a deployment's policy.

export const SANCTIONED_ENDPOINT_IDS = new Set<string>([
  'anthropic-api',
  'aws-bedrock',
  'azure-openai',
  'ollama-local',
]);

export interface ProviderMetadata {
  provider: string;
  hq: string;
  endpoints: number;
  notes: string;
}

// Lightweight provider catalog used to enrich dashboard summaries
export const PROVIDER_METADATA: ProviderMetadata[] = [
  { provider: 'Anthropic', hq: 'San Francisco, US', endpoints: 2, notes: 'API appears on the fictional sample allowlist.' },
  { provider: 'OpenAI', hq: 'San Francisco, US', endpoints: 3, notes: 'Consumer web use is a sample review trigger.' },
  { provider: 'Google', hq: 'Mountain View, US', endpoints: 3, notes: 'Sample catalog distinguishes API and consumer web entries.' },
  { provider: 'Microsoft', hq: 'Redmond, US', endpoints: 2, notes: 'Azure OpenAI appears on the fictional sample allowlist.' },
  { provider: 'AWS', hq: 'Seattle, US', endpoints: 1, notes: 'Bedrock appears on the fictional sample allowlist.' },
  { provider: 'Cohere', hq: 'Toronto, CA', endpoints: 1, notes: 'Mainstream alternative.' },
  { provider: 'Mistral', hq: 'Paris, FR', endpoints: 1, notes: 'Catalog entry; verify actual processing location.' },
  { provider: 'DeepSeek', hq: 'Hangzhou, CN', endpoints: 1, notes: 'Illustrative regional review flag; verify actual processing location.' },
  { provider: 'Alibaba', hq: 'Hangzhou, CN', endpoints: 1, notes: 'Illustrative regional review flag; verify actual processing location.' },
  { provider: 'Yandex', hq: 'Moscow, RU', endpoints: 1, notes: 'Illustrative regional review flag; verify applicable policy and law.' },
  { provider: 'Self-hosted', hq: 'On-prem', endpoints: 2, notes: 'Approval depends on the actual deployment.' },
];
