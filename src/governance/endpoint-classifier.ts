// LLM endpoint classifier. Recognizes traffic destined for known LLM/AI
// provider APIs and returns sanctioning status, provider, capability tier,
// and risk profile. The catalog covers commercial APIs, hosted inference
// platforms, and self-hosted gateways most likely to surface in shadow-AI.

export type SanctionStatus = 'sanctioned' | 'unsanctioned' | 'unknown';
export type Capability = 'chat' | 'completion' | 'embedding' | 'image-gen' | 'vision' | 'agent' | 'voice' | 'multi';
export type Tier = 'frontier' | 'mainstream' | 'open-weights' | 'inference-host' | 'self-hosted';

export interface LlmEndpoint {
  endpointId: string;
  provider: string;
  hostPattern: RegExp;
  pathPattern?: RegExp;
  capability: Capability;
  tier: Tier;
  defaultRisk: 'low' | 'medium' | 'high' | 'critical';
  sourceCountry?: string;
  notes?: string;
}

// Catalog covers ~30 of the most commonly observed LLM endpoints in
// enterprise traffic. Real production deployment would extend this with
// org-specific sanctioned-list and ingest threat-intel feeds.
const CATALOG: LlmEndpoint[] = [
  // Frontier commercial APIs
  { endpointId: 'anthropic-api', provider: 'Anthropic', hostPattern: /(^|\.)api\.anthropic\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'openai-api', provider: 'OpenAI', hostPattern: /(^|\.)api\.openai\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'google-genai', provider: 'Google', hostPattern: /(^|\.)generativelanguage\.googleapis\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'google-vertex', provider: 'Google', hostPattern: /(^|\.)aiplatform\.googleapis\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'azure-openai', provider: 'Microsoft', hostPattern: /\.openai\.azure\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'low', sourceCountry: 'US' },
  { endpointId: 'aws-bedrock', provider: 'AWS', hostPattern: /(^|\.)bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/i, capability: 'multi', tier: 'frontier', defaultRisk: 'low', sourceCountry: 'US' },

  // Mainstream APIs
  { endpointId: 'cohere-api', provider: 'Cohere', hostPattern: /(^|\.)api\.cohere\.(com|ai)$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'medium', sourceCountry: 'CA' },
  { endpointId: 'mistral-api', provider: 'Mistral', hostPattern: /(^|\.)api\.mistral\.ai$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'medium', sourceCountry: 'FR' },
  { endpointId: 'voyage-api', provider: 'Voyage', hostPattern: /(^|\.)api\.voyageai\.com$/i, capability: 'embedding', tier: 'mainstream', defaultRisk: 'low', sourceCountry: 'US' },

  // Inference hosts
  { endpointId: 'together-api', provider: 'Together AI', hostPattern: /(^|\.)api\.together\.(ai|xyz)$/i, capability: 'multi', tier: 'inference-host', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'replicate-api', provider: 'Replicate', hostPattern: /(^|\.)api\.replicate\.com$/i, capability: 'multi', tier: 'inference-host', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'fireworks-api', provider: 'Fireworks', hostPattern: /(^|\.)api\.fireworks\.ai$/i, capability: 'multi', tier: 'inference-host', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'groq-api', provider: 'Groq', hostPattern: /(^|\.)api\.groq\.com$/i, capability: 'multi', tier: 'inference-host', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'huggingface-inference', provider: 'Hugging Face', hostPattern: /(^|\.)api-inference\.huggingface\.co$/i, capability: 'multi', tier: 'inference-host', defaultRisk: 'medium', sourceCountry: 'US' },

  // Image / video / voice
  { endpointId: 'stability-api', provider: 'Stability AI', hostPattern: /(^|\.)api\.stability\.ai$/i, capability: 'image-gen', tier: 'mainstream', defaultRisk: 'medium', sourceCountry: 'UK' },
  { endpointId: 'elevenlabs-api', provider: 'ElevenLabs', hostPattern: /(^|\.)api\.elevenlabs\.io$/i, capability: 'voice', tier: 'mainstream', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'openai-dalle', provider: 'OpenAI', hostPattern: /(^|\.)api\.openai\.com$/i, pathPattern: /\/v1\/images\b/i, capability: 'image-gen', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },

  // Higher-risk regions / data residency
  { endpointId: 'deepseek-api', provider: 'DeepSeek', hostPattern: /(^|\.)api\.deepseek\.com$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'high', sourceCountry: 'CN', notes: 'Data residency / export-control concern.' },
  { endpointId: 'qwen-api', provider: 'Alibaba', hostPattern: /(^|\.)dashscope\.aliyuncs\.com$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'high', sourceCountry: 'CN', notes: 'Data residency / export-control concern.' },
  { endpointId: 'kimi-api', provider: 'Moonshot', hostPattern: /(^|\.)api\.moonshot\.cn$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'high', sourceCountry: 'CN' },
  { endpointId: 'yandex-gpt', provider: 'Yandex', hostPattern: /(^|\.)llm\.api\.cloud\.yandex\.net$/i, capability: 'multi', tier: 'mainstream', defaultRisk: 'critical', sourceCountry: 'RU', notes: 'Sanctions / export-control concern.' },

  // Consumer-grade interfaces (browser-based; usually shadow-AI)
  { endpointId: 'chatgpt-web', provider: 'OpenAI', hostPattern: /(^|\.)chatgpt\.com$/i, capability: 'chat', tier: 'frontier', defaultRisk: 'high', sourceCountry: 'US', notes: 'Consumer web interface; likely shadow-AI.' },
  { endpointId: 'claude-ai-web', provider: 'Anthropic', hostPattern: /(^|\.)claude\.ai$/i, capability: 'chat', tier: 'frontier', defaultRisk: 'high', sourceCountry: 'US', notes: 'Consumer web interface; likely shadow-AI.' },
  { endpointId: 'gemini-web', provider: 'Google', hostPattern: /(^|\.)gemini\.google\.com$/i, capability: 'chat', tier: 'frontier', defaultRisk: 'high', sourceCountry: 'US', notes: 'Consumer web interface; likely shadow-AI.' },
  { endpointId: 'copilot-web', provider: 'Microsoft', hostPattern: /(^|\.)copilot\.microsoft\.com$/i, capability: 'chat', tier: 'frontier', defaultRisk: 'medium', sourceCountry: 'US' },
  { endpointId: 'perplexity', provider: 'Perplexity', hostPattern: /(^|\.)perplexity\.ai$/i, capability: 'chat', tier: 'mainstream', defaultRisk: 'high', sourceCountry: 'US', notes: 'Consumer search/chat; likely shadow-AI.' },
  { endpointId: 'character-ai', provider: 'Character.AI', hostPattern: /(^|\.)character\.ai$/i, capability: 'chat', tier: 'mainstream', defaultRisk: 'high', sourceCountry: 'US' },

  // Self-hosted patterns
  { endpointId: 'ollama-local', provider: 'Self-hosted (Ollama)', hostPattern: /^(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$/, pathPattern: /\/api\/(generate|chat|embeddings)\b/i, capability: 'multi', tier: 'self-hosted', defaultRisk: 'low', notes: 'Self-hosted inference; verify org-sanctioned.' },
  { endpointId: 'vllm-local', provider: 'Self-hosted (vLLM)', hostPattern: /^(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$/, pathPattern: /\/v1\/(chat\/completions|completions|embeddings)\b/i, capability: 'multi', tier: 'self-hosted', defaultRisk: 'low' },
];

export interface ClassificationResult {
  matched: boolean;
  endpointId: string | null;
  provider: string | null;
  capability: Capability | null;
  tier: Tier | null;
  defaultRisk: 'low' | 'medium' | 'high' | 'critical' | null;
  sourceCountry: string | null;
  notes: string | null;
}

function parseUrl(input: string): { host: string; path: string } | null {
  // Best-effort URL parse; tolerate scheme-less hosts and bare hostnames
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  try {
    const u = new URL(s);
    return { host: u.hostname.toLowerCase(), path: u.pathname || '/' };
  } catch {
    return null;
  }
}

export function classifyEndpoint(urlOrHost: string): ClassificationResult {
  const parsed = parseUrl(urlOrHost);
  if (!parsed) {
    return { matched: false, endpointId: null, provider: null, capability: null, tier: null, defaultRisk: null, sourceCountry: null, notes: null };
  }

  // Iterate catalog; a path-specific entry beats a generic host match
  let bestMatch: LlmEndpoint | null = null;
  let bestScore = -1;
  for (const ep of CATALOG) {
    if (!ep.hostPattern.test(parsed.host)) continue;
    let score = 1;
    if (ep.pathPattern) {
      if (!ep.pathPattern.test(parsed.path)) continue;
      score = 2;
    }
    if (score > bestScore) {
      bestScore = score;
      bestMatch = ep;
    }
  }

  if (!bestMatch) {
    return { matched: false, endpointId: null, provider: null, capability: null, tier: null, defaultRisk: null, sourceCountry: null, notes: null };
  }

  return {
    matched: true,
    endpointId: bestMatch.endpointId,
    provider: bestMatch.provider,
    capability: bestMatch.capability,
    tier: bestMatch.tier,
    defaultRisk: bestMatch.defaultRisk,
    sourceCountry: bestMatch.sourceCountry ?? null,
    notes: bestMatch.notes ?? null,
  };
}

export function listKnownEndpoints(): Array<Omit<LlmEndpoint, 'hostPattern' | 'pathPattern'> & { hostPattern: string; pathPattern?: string }> {
  return CATALOG.map((ep) => ({
    endpointId: ep.endpointId,
    provider: ep.provider,
    hostPattern: ep.hostPattern.source,
    pathPattern: ep.pathPattern?.source,
    capability: ep.capability,
    tier: ep.tier,
    defaultRisk: ep.defaultRisk,
    sourceCountry: ep.sourceCountry,
    notes: ep.notes,
  }));
}

export interface SanctionedList {
  sanctionedEndpointIds: Set<string>;
}

export function sanctionStatus(endpointId: string | null, sanctioned: SanctionedList): SanctionStatus {
  if (!endpointId) return 'unknown';
  if (sanctioned.sanctionedEndpointIds.has(endpointId)) return 'sanctioned';
  return 'unsanctioned';
}
