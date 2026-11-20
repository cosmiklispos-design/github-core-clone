// github-core-clone-01 entry: one process, a standalone GitHub-compatible forge.
//
// Lifecycle (the env <-> entry contract):
//   1. MAKEFUN_ENV_URL names the env origin. Bind an ephemeral port (listen(0)).
//   2. POST $MAKEFUN_ENV_URL/register {"port": N}; the env dials the address the
//      request came from plus N as the base URL from then on.
//   3. GET $MAKEFUN_ENV_URL/done until {"done": true}, then close and exit 0.
//      The env answers at once ({"done": false} while the suite runs), so this is
//      a poll with a short backoff, never a long-held request.
//   4. Without MAKEFUN_ENV_URL (local development) just listen and serve: the
//      port comes from PORT, or an ephemeral one that is printed on stdout.
//
// The server itself lives in app.ts (createApp). This file is only the lifecycle.

import { createApp } from './app.ts';

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');

const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

/** POST the bound port until the env accepts it (200) or reports a first register won (409). */
async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

/** Poll GET /done until it answers {"done": true}; never return before that. */
async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet, or the poll timed out: not done, poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  const server = createApp();
  const localPort = Number(process.env.PORT ?? 0);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number.isFinite(localPort) && localPort > 0 ? localPort : 0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on port ${address.port}\n`);
  // The env may end a trial by killing the process; shut the server down cleanly.
  process.on('SIGTERM', () => {
    server.close();
    process.exit(0);
  });
  if (ENV_URL === '') {
    // Local development: no env to register with, just serve until killed.
    process.stdout.write('[entry] no MAKEFUN_ENV_URL set: serving locally, no register/done loop\n');
    await new Promise<void>(() => {});
    return;
  }
  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
