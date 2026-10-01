import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const repoRoot = path.join(__dirname, '..');
const entry = path.join(repoRoot, 'dist', 'index.js');

function startCompiled(overrides: Record<string, string | undefined>) {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, PORT: '31234' };
  delete childEnv.NODE_ENV;
  delete childEnv.SHADOW_LOCAL_FIXTURE;
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete childEnv[key];
    else childEnv[key] = value;
  }
  // dotenv reads from cwd; docs contains no local .env and keeps the child
  // isolated from any developer-owned root .env file.
  return spawnSync(process.execPath, [entry], {
    cwd: path.join(repoRoot, 'docs'), env: childEnv, encoding: 'utf8', timeout: 5000,
  });
}

test('compiled server refuses missing mode or missing local fixture opt-in', () => {
  for (const overrides of [
    { SHADOW_LOCAL_FIXTURE: '1' },
    { NODE_ENV: 'development' },
    { NODE_ENV: 'test' },
    { NODE_ENV: 'production', SHADOW_LOCAL_FIXTURE: '1' },
    { NODE_ENV: 'staging', SHADOW_LOCAL_FIXTURE: '1' },
  ]) {
    const result = startCompiled(overrides);
    assert.equal(result.status, 1, JSON.stringify(overrides));
    assert.match(result.stderr, /Synthetic local demo requires NODE_ENV=development or test and SHADOW_LOCAL_FIXTURE=1/);
  }
});

test('compiled app cannot be imported without explicit local fixture opt-in', () => {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, PORT: '31234', NODE_ENV: 'development' };
  delete childEnv.SHADOW_LOCAL_FIXTURE;
  const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(entry)})`], {
    cwd: path.join(repoRoot, 'docs'), env: childEnv, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Synthetic local demo requires NODE_ENV=development or test and SHADOW_LOCAL_FIXTURE=1/);
});

test('compiled server refuses malformed or out-of-range ports', () => {
  for (const port of ['0', '65536', '3000junk', '-1']) {
    const result = startCompiled({ NODE_ENV: 'development', SHADOW_LOCAL_FIXTURE: '1', PORT: port });
    assert.equal(result.status, 1, port);
    assert.match(result.stderr, /PORT must be an integer from 1 to 65535/);
  }
});
