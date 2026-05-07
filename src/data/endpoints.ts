// Org sanctioned-list. In production this would come from a config service
// or admin UI. For demo: org has approved Anthropic API + AWS Bedrock +
// Azure OpenAI + their internal Ollama deployment.

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
  { provider: 'Anthropic', hq: 'San Francisco, US', endpoints: 2, notes: 'Sanctioned for production use.' },
  { provider: 'OpenAI', hq: 'San Francisco, US', endpoints: 3, notes: 'Web interface flagged as shadow-AI.' },
  { provider: 'Google', hq: 'Mountain View, US', endpoints: 3, notes: 'Mixed: Vertex sanctioned, Gemini web flagged.' },
  { provider: 'Microsoft', hq: 'Redmond, US', endpoints: 2, notes: 'Azure OpenAI sanctioned.' },
  { provider: 'AWS', hq: 'Seattle, US', endpoints: 1, notes: 'Sanctioned via Bedrock.' },
  { provider: 'Cohere', hq: 'Toronto, CA', endpoints: 1, notes: 'Mainstream alternative.' },
  { provider: 'Mistral', hq: 'Paris, FR', endpoints: 1, notes: 'EU-hosted; data residency option.' },
  { provider: 'DeepSeek', hq: 'Hangzhou, CN', endpoints: 1, notes: 'High risk: data residency + export-control concern.' },
  { provider: 'Alibaba', hq: 'Hangzhou, CN', endpoints: 1, notes: 'High risk: data residency.' },
  { provider: 'Yandex', hq: 'Moscow, RU', endpoints: 1, notes: 'Critical: sanctions / export-control concern.' },
  { provider: 'Self-hosted', hq: 'On-prem', endpoints: 2, notes: 'Sanctioned per deployment.' },
];
