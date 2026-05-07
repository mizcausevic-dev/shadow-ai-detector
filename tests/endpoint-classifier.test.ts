import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyEndpoint, sanctionStatus, listKnownEndpoints } from '../src/governance/endpoint-classifier';

test('classifyEndpoint: anthropic api matched', () => {
  const r = classifyEndpoint('https://api.anthropic.com/v1/messages');
  assert.equal(r.matched, true);
  assert.equal(r.endpointId, 'anthropic-api');
  assert.equal(r.provider, 'Anthropic');
});

test('classifyEndpoint: openai dalle path beats generic openai', () => {
  const r = classifyEndpoint('https://api.openai.com/v1/images/generations');
  assert.equal(r.endpointId, 'openai-dalle');
  assert.equal(r.capability, 'image-gen');
});

test('classifyEndpoint: bedrock regional host matched', () => {
  const r = classifyEndpoint('https://bedrock-runtime.us-west-2.amazonaws.com/model/foo/invoke');
  assert.equal(r.endpointId, 'aws-bedrock');
});

test('classifyEndpoint: deepseek is high default risk', () => {
  const r = classifyEndpoint('https://api.deepseek.com/chat/completions');
  assert.equal(r.endpointId, 'deepseek-api');
  assert.equal(r.defaultRisk, 'high');
  assert.equal(r.sourceCountry, 'CN');
});

test('classifyEndpoint: yandex is critical default risk', () => {
  const r = classifyEndpoint('https://llm.api.cloud.yandex.net/foundationModels/v1/completion');
  assert.equal(r.endpointId, 'yandex-gpt');
  assert.equal(r.defaultRisk, 'critical');
});

test('classifyEndpoint: chatgpt.com web flagged shadow-AI', () => {
  const r = classifyEndpoint('https://chatgpt.com/backend-api/conversation');
  assert.equal(r.endpointId, 'chatgpt-web');
  assert.equal(r.defaultRisk, 'high');
  assert.match(r.notes ?? '', /consumer/i);
});

test('classifyEndpoint: ollama on private IP matched', () => {
  const r = classifyEndpoint('http://10.4.12.100/api/chat');
  assert.equal(r.endpointId, 'ollama-local');
  assert.equal(r.tier, 'self-hosted');
});

test('classifyEndpoint: random non-LLM URL not matched', () => {
  const r = classifyEndpoint('https://api.github.com/repos/foo/bar');
  assert.equal(r.matched, false);
  assert.equal(r.endpointId, null);
});

test('classifyEndpoint: bare hostname tolerated', () => {
  const r = classifyEndpoint('api.openai.com');
  assert.equal(r.matched, true);
  assert.equal(r.provider, 'OpenAI');
});

test('classifyEndpoint: malformed URL returns unmatched', () => {
  const r = classifyEndpoint('not a url at all !@#$');
  // URL parser will tolerate most strings; verify the catalog match still negative
  assert.equal(r.matched, false);
});

test('sanctionStatus: known sanctioned id', () => {
  const s = sanctionStatus('anthropic-api', { sanctionedEndpointIds: new Set(['anthropic-api', 'aws-bedrock']) });
  assert.equal(s, 'sanctioned');
});

test('sanctionStatus: matched but unsanctioned', () => {
  const s = sanctionStatus('deepseek-api', { sanctionedEndpointIds: new Set(['anthropic-api']) });
  assert.equal(s, 'unsanctioned');
});

test('sanctionStatus: null endpointId is unknown', () => {
  const s = sanctionStatus(null, { sanctionedEndpointIds: new Set() });
  assert.equal(s, 'unknown');
});

test('listKnownEndpoints: returns serializable catalog', () => {
  const list = listKnownEndpoints();
  assert.ok(list.length >= 25);
  assert.ok(list.every((e) => typeof e.hostPattern === 'string'));
  assert.ok(list.some((e) => e.endpointId === 'anthropic-api'));
});
