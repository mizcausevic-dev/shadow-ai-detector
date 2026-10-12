import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyEndpoint } from '../src/governance/endpoint-classifier';
import { scanPayload } from '../src/governance/payload-scanner';

// Hand-labeled synthetic challenge cases exercise both matches and near misses.
// Passing this set is a regression check, not a field precision/recall estimate.
const endpointCases: Array<{ name: string; input: string; expected: string | null }> = [
  { name: 'generic API', input: 'https://api.openai.com/v1/chat/completions', expected: 'openai-api' },
  { name: 'path-specific image API', input: 'https://api.openai.com/v1/images/generations', expected: 'openai-dalle' },
  { name: 'bare hostname', input: 'api.anthropic.com', expected: 'anthropic-api' },
  { name: 'DNS root dot', input: 'https://api.openai.com./v1/chat/completions', expected: 'openai-api' },
  { name: 'regional Bedrock API', input: 'https://bedrock-runtime.us-east-1.amazonaws.com/model/demo/invoke', expected: 'aws-bedrock' },
  { name: 'private Ollama path', input: 'http://192.168.1.12/api/chat', expected: 'ollama-local' },
  { name: 'consumer interface', input: 'https://chatgpt.com/', expected: 'chatgpt-web' },
  { name: 'explicit HTTPS port', input: 'https://api.openai.com:443/v1/chat/completions', expected: 'openai-api' },
  { name: 'lookalike suffix', input: 'https://api.openai.com.evil.example/v1/chat/completions', expected: null },
  { name: 'user-info trick', input: 'https://api.openai.com@evil.example/v1/chat/completions', expected: null },
  { name: 'provider only in query', input: 'https://evil.example/?next=https://api.openai.com/v1', expected: null },
  { name: 'unrelated API', input: 'https://api.github.com/repos/demo', expected: null },
  { name: 'non-HTTP scheme', input: 'ftp://api.openai.com/v1/chat/completions', expected: null },
];

const payloadCases: Array<{ name: string; payload: string; pattern: string; expected: boolean }> = [
  { name: 'valid demo card', payload: 'Card 4111-1111-1111-1111', pattern: 'credit-card', expected: true },
  { name: 'invalid card checksum', payload: 'Order 4532-1234-5678-9010', pattern: 'credit-card', expected: false },
  { name: 'valid second candidate', payload: 'Order 4532-1234-5678-9010, card 4111-1111-1111-1111', pattern: 'credit-card', expected: true },
  { name: 'labeled diagnosis', payload: 'ICD-10: E11.9', pattern: 'icd-code', expected: true },
  { name: 'unlabeled project code', payload: 'Project E11.9', pattern: 'icd-code', expected: false },
  { name: 'synthetic GitHub-shaped token', payload: `key ghp_${'a'.repeat(36)}`, pattern: 'github-pat', expected: true },
  { name: 'short token prefix', payload: 'key ghp_example', pattern: 'github-pat', expected: false },
  { name: 'synthetic AWS-shaped ID', payload: `key AKIA${'A'.repeat(16)}`, pattern: 'aws-access-key', expected: true },
  { name: 'short AWS prefix', payload: 'key AKIA123', pattern: 'aws-access-key', expected: false },
  { name: 'classification marker', payload: 'CONFIDENTIAL: review this', pattern: 'classified-marker', expected: true },
  { name: 'near-word marker', payload: 'The secretary will review this', pattern: 'classified-marker', expected: false },
  { name: 'email address', payload: 'Contact user@example.test', pattern: 'email', expected: true },
  { name: 'obfuscated email', payload: 'Contact user at example dot test', pattern: 'email', expected: false },
  { name: 'credentialed connection string', payload: 'postgres://demo:placeholder@db.example.test/demo', pattern: 'connection-string', expected: true },
  { name: 'connection without password', payload: 'postgres://db.example.test/demo', pattern: 'connection-string', expected: false },
  { name: 'SSN-like format', payload: 'SSN 123-45-6789', pattern: 'ssn-us', expected: true },
  { name: 'short SSN-like format', payload: 'Case 123-45-678', pattern: 'ssn-us', expected: false },
];

test('synthetic endpoint challenge set has no wrong labels', (t) => {
  for (const item of endpointCases) {
    assert.equal(classifyEndpoint(item.input).endpointId, item.expected, item.name);
  }
  t.diagnostic(`${endpointCases.length} hand-labeled endpoint cases passed`);
});

test('synthetic payload challenge set has no wrong labels', (t) => {
  for (const item of payloadCases) {
    const detected = scanPayload(item.payload).hits.some((hit) => hit.patternName === item.pattern);
    assert.equal(detected, item.expected, item.name);
  }
  t.diagnostic(`${payloadCases.length} hand-labeled payload cases passed`);
});
