import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPayload } from '../src/governance/payload-scanner';

test('scanPayload: clean payload yields no hits', () => {
  const r = scanPayload('Just summarize this article about cats please.');
  assert.equal(r.hits.length, 0);
  assert.equal(r.highestSeverity, null);
  assert.equal(r.shouldBlock, false);
});

test('scanPayload: SSN detected as high', () => {
  const r = scanPayload('Customer SSN is 123-45-6789, please verify.');
  assert.ok(r.hits.some((h) => h.patternName === 'ssn-us'));
  assert.equal(r.highestSeverity, 'high');
  assert.equal(r.byCategory.pii, 1);
});

test('scanPayload: AWS access key flagged critical', () => {
  const r = scanPayload('Use this key: AKIAIOSFODNN7EXAMPLE for the S3 bucket');
  assert.ok(r.hits.some((h) => h.patternName === 'aws-access-key'));
  assert.equal(r.highestSeverity, 'critical');
  assert.equal(r.shouldBlock, true);
});

test('scanPayload: classified marker flagged critical', () => {
  const r = scanPayload('CONFIDENTIAL: Do not share outside the company.');
  assert.ok(r.hits.some((h) => h.patternName === 'classified-marker'));
  assert.equal(r.highestSeverity, 'critical');
});

test('scanPayload: credit card flagged critical', () => {
  const r = scanPayload('Card: 4532-1234-5678-9010 expired');
  assert.ok(r.hits.some((h) => h.patternName === 'credit-card'));
  assert.equal(r.shouldBlock, true);
});

test('scanPayload: GitHub PAT flagged critical', () => {
  const r = scanPayload('Set GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789');
  assert.ok(r.hits.some((h) => h.patternName === 'github-pat'));
});

test('scanPayload: connection string flagged high', () => {
  const r = scanPayload('Use postgres://admin:S3cret123@db-prod.internal:5432/users for testing');
  assert.ok(r.hits.some((h) => h.patternName === 'connection-string'));
  assert.equal(r.byCategory['source-code'], 1);
});

test('scanPayload: snippet is redacted', () => {
  const r = scanPayload('GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789');
  const hit = r.hits.find((h) => h.patternName === 'github-pat');
  assert.ok(hit);
  // Should be redacted form, not the raw token
  assert.match(hit!.matchedSnippet, /\*+/);
  assert.doesNotMatch(hit!.matchedSnippet, /aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/);
});

test('scanPayload: multiple categories aggregated', () => {
  const r = scanPayload('CONFIDENTIAL info: SSN 123-45-6789 and ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789');
  assert.ok(r.byCategory.pii >= 1);
  assert.ok(r.byCategory.credential >= 1);
  assert.ok(r.byCategory['internal-marker'] >= 1);
  assert.equal(r.highestSeverity, 'critical');
});

test('scanPayload: low severity does not trigger block', () => {
  const r = scanPayload('Email me at user@example.com');
  assert.equal(r.highestSeverity, 'low');
  assert.equal(r.shouldBlock, false);
});
