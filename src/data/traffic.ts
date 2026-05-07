// Sample traffic captures across an enterprise's egress proxy. Mix of:
// - Sanctioned LLM use (clean)
// - Unsanctioned but US-based LLM use (shadow-AI lite)
// - Unsanctioned consumer web LLM (chatgpt.com, claude.ai) with PII
// - Source-code uploads to inference hosts
// - High-risk country endpoints (CN/RU)
// - Volume anomalies

import type { TrafficEvent } from '../governance/risk-scorer';

export const TRAFFIC_EVENTS: TrafficEvent[] = [
  // Sanctioned production use
  {
    eventId: 'evt_001',
    timestamp: '2026-05-07T08:14:22Z',
    url: 'https://api.anthropic.com/v1/messages',
    method: 'POST',
    payloadSnippet: '{"messages": [{"role": "user", "content": "Summarize quarterly metrics"}]}',
    user: 'alice.chen@corp.com',
    department: 'data-platform',
    sourceHost: '10.4.12.18',
    bytesUp: 2048,
    bytesDown: 12288,
  },
  {
    eventId: 'evt_002',
    timestamp: '2026-05-07T08:22:11Z',
    url: 'https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3/invoke',
    method: 'POST',
    payloadSnippet: '{"prompt": "Generate test data for fixtures"}',
    user: 'bob.engineer@corp.com',
    department: 'platform-eng',
    sourceHost: '10.4.12.45',
    bytesUp: 1536,
    bytesDown: 8192,
  },

  // Shadow-AI: consumer web with PII leak
  {
    eventId: 'evt_003',
    timestamp: '2026-05-07T09:11:05Z',
    url: 'https://chatgpt.com/backend-api/conversation',
    method: 'POST',
    payloadSnippet: 'Here is customer record: name John Smith, SSN 123-45-6789, DOB: 03/14/1985, please draft outreach.',
    user: 'carol.sales@corp.com',
    department: 'sales',
    sourceHost: '10.5.20.118',
    bytesUp: 4096,
    bytesDown: 16384,
  },
  {
    eventId: 'evt_004',
    timestamp: '2026-05-07T09:33:48Z',
    url: 'https://claude.ai/api/organizations/abc/chat_conversations',
    method: 'POST',
    payloadSnippet: 'Help me write Q3 strategy memo. CONFIDENTIAL: Project Cobalt acquisition target $4.2B.',
    user: 'dave.exec@corp.com',
    department: 'executive',
    sourceHost: '10.6.30.4',
    bytesUp: 8192,
    bytesDown: 24576,
  },

  // Unsanctioned source code upload
  {
    eventId: 'evt_005',
    timestamp: '2026-05-07T10:02:33Z',
    url: 'https://api.openai.com/v1/chat/completions',
    method: 'POST',
    payloadSnippet: 'Refactor this Python: aws_secret_access_key="abcdef0123456789ABCDEF0123456789abcdefgh"',
    user: 'eve.dev@corp.com',
    department: 'engineering',
    sourceHost: '10.4.15.22',
    bytesUp: 16384,
    bytesDown: 8192,
  },
  {
    eventId: 'evt_006',
    timestamp: '2026-05-07T10:18:42Z',
    url: 'https://api.together.ai/v1/chat/completions',
    method: 'POST',
    payloadSnippet: '{"messages":[{"role":"user","content":"Debug: postgres://admin:S3cret123@db-prod.internal:5432/users"}]}',
    user: 'frank.dev@corp.com',
    department: 'engineering',
    sourceHost: '10.4.15.31',
    bytesUp: 5120,
    bytesDown: 4096,
  },

  // Critical: foreign-hosted LLM with payload
  {
    eventId: 'evt_007',
    timestamp: '2026-05-07T10:45:19Z',
    url: 'https://api.deepseek.com/chat/completions',
    method: 'POST',
    payloadSnippet: 'Translate technical spec for project. INTERNAL ONLY material attached.',
    user: 'grace.intern@corp.com',
    department: 'product',
    sourceHost: '10.7.40.56',
    bytesUp: 32768,
    bytesDown: 8192,
  },
  {
    eventId: 'evt_008',
    timestamp: '2026-05-07T11:02:08Z',
    url: 'https://llm.api.cloud.yandex.net/foundationModels/v1/completion',
    method: 'POST',
    payloadSnippet: 'Generate marketing copy for new feature launch',
    user: 'henry.marketing@corp.com',
    department: 'marketing',
    sourceHost: '10.8.50.14',
    bytesUp: 1024,
    bytesDown: 2048,
  },

  // Volume anomaly: large upload to unsanctioned endpoint
  {
    eventId: 'evt_009',
    timestamp: '2026-05-07T11:30:55Z',
    url: 'https://api.replicate.com/v1/predictions',
    method: 'POST',
    payloadSnippet: 'Process 200-page contract PDF; extract terms and obligations.',
    user: 'iris.legal@corp.com',
    department: 'legal',
    sourceHost: '10.9.60.8',
    bytesUp: 524288,
    bytesDown: 65536,
  },

  // Mainstream EU-hosted alt
  {
    eventId: 'evt_010',
    timestamp: '2026-05-07T11:48:22Z',
    url: 'https://api.mistral.ai/v1/chat/completions',
    method: 'POST',
    payloadSnippet: 'Summarize this meeting transcript',
    user: 'jack.product@corp.com',
    department: 'product',
    sourceHost: '10.7.40.71',
    bytesUp: 8192,
    bytesDown: 4096,
  },

  // Self-hosted (sanctioned)
  {
    eventId: 'evt_011',
    timestamp: '2026-05-07T12:05:14Z',
    url: 'http://10.4.12.100/api/chat',
    method: 'POST',
    payloadSnippet: '{"model":"llama3.1","messages":[{"role":"user","content":"Suggest unit test cases"}]}',
    user: 'kate.platform@corp.com',
    department: 'platform-eng',
    sourceHost: '10.4.12.18',
    bytesUp: 2048,
    bytesDown: 16384,
  },

  // Non-LLM traffic (control)
  {
    eventId: 'evt_012',
    timestamp: '2026-05-07T12:14:30Z',
    url: 'https://api.github.com/repos/corp/internal',
    method: 'GET',
    payloadSnippet: '',
    user: 'leo.dev@corp.com',
    department: 'engineering',
    sourceHost: '10.4.15.42',
    bytesUp: 512,
    bytesDown: 4096,
  },

  // Perplexity research with PII
  {
    eventId: 'evt_013',
    timestamp: '2026-05-07T13:22:18Z',
    url: 'https://www.perplexity.ai/api/search',
    method: 'POST',
    payloadSnippet: 'Research customer profile: jane.doe@bigclient.com, phone (555) 123-4567',
    user: 'mike.sales@corp.com',
    department: 'sales',
    sourceHost: '10.5.20.119',
    bytesUp: 1024,
    bytesDown: 8192,
  },

  // GitHub PAT in code review prompt
  {
    eventId: 'evt_014',
    timestamp: '2026-05-07T14:08:42Z',
    url: 'https://api.openai.com/v1/chat/completions',
    method: 'POST',
    payloadSnippet: 'Review my CI script. Set GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 in env.',
    user: 'nina.devops@corp.com',
    department: 'engineering',
    sourceHost: '10.4.15.55',
    bytesUp: 3072,
    bytesDown: 4096,
  },

  // Gemini web with credit card
  {
    eventId: 'evt_015',
    timestamp: '2026-05-07T15:11:20Z',
    url: 'https://gemini.google.com/app',
    method: 'POST',
    payloadSnippet: 'Help draft refund email for charge on card 4532-1234-5678-9010',
    user: 'olivia.finance@corp.com',
    department: 'finance',
    sourceHost: '10.10.70.22',
    bytesUp: 2048,
    bytesDown: 4096,
  },

  // ElevenLabs voice cloning attempt
  {
    eventId: 'evt_016',
    timestamp: '2026-05-07T15:33:11Z',
    url: 'https://api.elevenlabs.io/v1/text-to-speech/abc123',
    method: 'POST',
    payloadSnippet: 'Generate voice for promotional content',
    user: 'paul.creative@corp.com',
    department: 'marketing',
    sourceHost: '10.8.50.18',
    bytesUp: 4096,
    bytesDown: 65536,
  },
];
