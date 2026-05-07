import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessEvent, assessFleet, type TrafficEvent } from '../src/governance/risk-scorer';
import { rollupByDepartment } from '../src/governance/department-rollup';

const SANCTIONED = new Set(['anthropic-api', 'aws-bedrock', 'azure-openai', 'ollama-local']);

function ev(o: Partial<TrafficEvent>): TrafficEvent {
  return {
    eventId: o.eventId ?? 'evt_test',
    timestamp: o.timestamp ?? '2026-05-07T10:00:00Z',
    url: o.url ?? 'https://api.anthropic.com/v1/messages',
    method: o.method ?? 'POST',
    payloadSnippet: o.payloadSnippet ?? '',
    user: o.user ?? 'test@corp.com',
    department: o.department ?? 'engineering',
    sourceHost: o.sourceHost ?? '10.0.0.1',
    bytesUp: o.bytesUp ?? 1024,
    bytesDown: o.bytesDown ?? 2048,
  };
}

test('assessEvent: sanctioned + clean payload is minimal', () => {
  const r = assessEvent(ev({ url: 'https://api.anthropic.com/v1/messages', payloadSnippet: 'summarize this' }), SANCTIONED);
  assert.equal(r.matched, true);
  assert.equal(r.sanctionStatus, 'sanctioned');
  assert.ok(r.riskScore < 25, `score=${r.riskScore}`);
  assert.equal(r.riskTier, 'minimal');
});

test('assessEvent: unsanctioned + clean is elevated', () => {
  const r = assessEvent(ev({ url: 'https://api.together.ai/v1/chat/completions', payloadSnippet: 'hello' }), SANCTIONED);
  assert.equal(r.sanctionStatus, 'unsanctioned');
  assert.ok(['elevated', 'high'].includes(r.riskTier), `tier=${r.riskTier}`);
});

test('assessEvent: chatgpt.com + SSN is critical', () => {
  const r = assessEvent(ev({
    url: 'https://chatgpt.com/backend-api/conversation',
    payloadSnippet: 'Customer SSN is 123-45-6789, draft email please.',
  }), SANCTIONED);
  assert.equal(r.matched, true);
  assert.equal(r.riskTier, 'critical');
  assert.ok(r.signals.some((s) => s.includes('pii')));
});

test('assessEvent: Yandex traffic flags critical and country signal', () => {
  const r = assessEvent(ev({
    url: 'https://llm.api.cloud.yandex.net/foundationModels/v1/completion',
    payloadSnippet: 'plain content',
  }), SANCTIONED);
  assert.equal(r.matched, true);
  assert.ok(['high', 'critical'].includes(r.riskTier));
  assert.ok(r.signals.some((s) => s.includes('RU')));
});

test('assessEvent: large upload triggers volume signal', () => {
  const r = assessEvent(ev({
    url: 'https://api.together.ai/v1/chat/completions',
    payloadSnippet: 'analysis request',
    bytesUp: 600 * 1024,
  }), SANCTIONED);
  assert.ok(r.signals.some((s) => s.toLowerCase().includes('upload size')));
});

test('assessEvent: non-LLM URL with clean payload is minimal', () => {
  const r = assessEvent(ev({
    url: 'https://api.github.com/repos/foo/bar',
    payloadSnippet: '',
  }), SANCTIONED);
  assert.equal(r.matched, false);
  assert.equal(r.riskTier, 'minimal');
});

test('assessEvent: AWS creds in OpenAI prompt flagged critical', () => {
  const r = assessEvent(ev({
    url: 'https://api.openai.com/v1/chat/completions',
    payloadSnippet: 'aws_secret_access_key="abcdef0123456789ABCDEF0123456789abcdefgh"',
  }), SANCTIONED);
  assert.equal(r.riskTier, 'critical');
  assert.equal(r.payloadHits.shouldBlock, true);
});

test('assessFleet: aggregates tiers and unsanctioned counts', () => {
  const events = [
    ev({ eventId: 'a', url: 'https://api.anthropic.com/v1/messages', user: 'u1', department: 'platform' }),
    ev({ eventId: 'b', url: 'https://chatgpt.com/api', user: 'u2', department: 'sales', payloadSnippet: 'SSN 123-45-6789' }),
    ev({ eventId: 'c', url: 'https://api.deepseek.com/chat', user: 'u3', department: 'product', payloadSnippet: 'CONFIDENTIAL' }),
  ];
  const fleet = assessFleet(events, SANCTIONED);
  assert.equal(fleet.summary.totalEvents, 3);
  assert.equal(fleet.summary.llmEvents, 3);
  assert.ok(fleet.summary.unsanctionedEvents >= 2);
  assert.ok(fleet.summary.byTier.critical >= 1);
});

test('assessFleet: top risk users sorted by maxScore', () => {
  const events = [
    ev({ eventId: '1', user: 'low@corp.com', department: 'eng', url: 'https://api.anthropic.com/v1/messages' }),
    ev({ eventId: '2', user: 'crit@corp.com', department: 'sales', url: 'https://chatgpt.com/api', payloadSnippet: 'SSN 123-45-6789 plus AKIAIOSFODNN7EXAMPLE' }),
  ];
  const fleet = assessFleet(events, SANCTIONED);
  assert.equal(fleet.summary.topRiskUsers[0].user, 'crit@corp.com');
});

test('rollupByDepartment: marketing + dept-level dataset produces ranking', () => {
  const events = [
    ev({ eventId: '1', user: 'a@corp.com', department: 'sales', url: 'https://chatgpt.com', payloadSnippet: 'SSN 123-45-6789' }),
    ev({ eventId: '2', user: 'b@corp.com', department: 'sales', url: 'https://chatgpt.com' }),
    ev({ eventId: '3', user: 'c@corp.com', department: 'engineering', url: 'https://api.anthropic.com/v1/messages' }),
  ];
  const fleet = assessFleet(events, SANCTIONED);
  const departments = rollupByDepartment(events, fleet.assessments);
  assert.ok(departments.length >= 2);
  // sales should be ranked above engineering due to unsanctioned + critical
  const sales = departments.find((d) => d.department === 'sales');
  const engineering = departments.find((d) => d.department === 'engineering');
  assert.ok(sales);
  assert.ok(engineering);
  assert.ok(sales!.exposureScore > engineering!.exposureScore, `sales=${sales!.exposureScore}, eng=${engineering!.exposureScore}`);
});

test('rollupByDepartment: throws on misaligned arrays', () => {
  assert.throws(() => rollupByDepartment([ev({})], []), /align/);
});

test('rollupByDepartment: clean department gets no recommended action', () => {
  const events = [
    ev({ eventId: '1', user: 'a@corp.com', department: 'platform', url: 'https://api.anthropic.com/v1/messages' }),
  ];
  const fleet = assessFleet(events, SANCTIONED);
  const departments = rollupByDepartment(events, fleet.assessments);
  const platform = departments.find((d) => d.department === 'platform');
  assert.ok(platform);
  assert.equal(platform!.exposureScore, 0);
  assert.match(platform!.recommendedAction, /compliant|monitor/i);
});
