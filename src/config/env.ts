import dotenv from 'dotenv';
import { canStartLocalDemo } from './local-boundary';
dotenv.config();

function readPort(raw: string | undefined): number {
  const text = raw ?? '3000';
  if (!/^\d{1,5}$/.test(text)) throw new Error('PORT must be an integer from 1 to 65535.');
  const port = Number(text);
  if (port < 1 || port > 65535) throw new Error('PORT must be an integer from 1 to 65535.');
  return port;
}

export const env = {
  port: readPort(process.env.PORT),
  nodeEnv: process.env.NODE_ENV,
  localFixtureOptIn: process.env.SHADOW_LOCAL_FIXTURE === '1',
};

if (!canStartLocalDemo(env.nodeEnv, env.localFixtureOptIn)) {
  throw new Error('Synthetic local demo requires NODE_ENV=development or test and SHADOW_LOCAL_FIXTURE=1.');
}
