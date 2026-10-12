# Disabled feed authorization boundary plan

## Goal

Make one representative feed analysis path enforce verified caller identity and server-owned tenant/resource authorization, while leaving the shipped runtime a loopback-only synthetic demo.

## Current state

The reviewed PR branch is a local fixture service. `src/index.ts` requires explicit development/test opt-in, binds loopback, and has no live feed, identity provider, tenant registry, or production target. The unprotected `/api/analyze` routes are synthetic-example tools only.

## Scope and acceptance

Add an opt-in `/api/feed/:resourceId/analyze/{payload,event,traffic}` router for injected, trusted configuration. Without configuration it must reject requests. With configuration it must verify a signed JWT from a pinned public key set, exact issuer and audience, expiry and age, scope, active-token status, tenant ownership, and a server-owned grant for its signed `client_id` and requested resource. Missing, malformed, revoked, cross-tenant, or ungranted credentials must be denied before body parsing or analysis. Tests will use generated keys and in-memory resource and grant registries on an ephemeral loopback listener. No real provider, credential, feed, data store, production listener, or release is introduced.

## Risks and release class

R3 if this path is ever reachable outside the synthetic loopback demo. A copied test key, permissive revocation callback, wrong resource registry, omitted quota, or proxy exposure would defeat the boundary. The route cannot be considered production ready on its own.

## Design and sequence

Use the maintained `jose` verifier rather than implementing JWT parsing. The app factory mounts a deny-by-default router. Tests may inject a pinned EdDSA public key set and server-owned resource and grant lookups; normal startup injects neither. A revocation/active-token callback is required and fails closed on error. Keep the existing local boundary ahead of the route and all body parsers. The injected app does not mount fixture or unprotected analysis routes.

1. Add the verifier and protected router; mount it through the app factory.
2. Test the complete HTTP path for permitted and denied requests, including local startup and route-disabled behavior.
3. Run build, tests, production dependency audit, secret scan, and diff review.
4. Update production evidence with remaining deployed-boundary requirements.

## Deployment and rollback

There is no configured production target or acceptable hosted rollback artifact. No deployment is allowed by this plan. Reverting this unmerged change leaves the existing loopback fixture behavior.

## Progress and outcome

- [x] Inspected branch, instructions, source, tests, release report, and current deployment boundary.
- [x] Implemented and verified the protected route with test-only generated keys and in-memory ownership/grant callbacks.
- [x] Reviewed the diff and recorded checks and residual risks below.

## Outcome observed 2026-10-01

The normal `createApp()` still mounts only the local synthetic fixture and returns 404 for feed routes; `NODE_ENV=production` remains a startup refusal. The injected test app mounts only health and signed-token feed analysis, without the unprotected `/api/analyze` or fixture routes. Its HTTP tests cover missing, malformed, forged, wrong issuer/audience, multi-audience, expired, too-old, revoked, wrong-tenant, same-tenant ungranted-client/resource, and backing-registry outage paths. A duplicated Authorization header is denied by Node's HTTP parser (400 or connection reset on local Node 24), or by the middleware if it reaches Express (401). The server remains healthy after that denial.

After a clean `npm.cmd ci --ignore-scripts` install, `npm.cmd test` exited 0 with 67/67 tests and a TypeScript build. `npm.cmd audit --omit=dev --audit-level=moderate` exited 0 with zero reported vulnerabilities. `gitleaks dir --no-banner --redact --exit-code 1 .` exited 0 after scanning about 211 KB and finding no leaks; this single method is not a verified-clean security audit. `git diff --check` exited 0 after normalizing the changed `src/index.ts` file to LF. The first sandboxed offline `npm.cmd ci --ignore-scripts --offline` failed with `EPERM` reading the npm cache outside the writable workspace; the approved retry exited 0. An intermediate test run failed because local Node 24 rejected duplicate Authorization fields before Express, sometimes with `ECONNRESET`; the test now recognizes both parser-level denial forms and was rerun successfully.

This code is not a deployed identity boundary. A real issuer must provide trustworthy `tenant_id` and `client_id` claims; active-token, resource, and grant callbacks need authoritative backing, timeouts, availability controls, and tests at the deployed boundary. A permissioned feed, trusted-ingress and distributed quotas, retention/deletion, field accuracy evidence, production target, monitoring, and an acceptable hosted rollback artifact are still absent. As verified against GitHub on 2026-10-01, draft PR #17 was open and unmerged at `3f253e66a7348d9e85bf8c7a1d02cf20ce9719d1`. The quota follow-up below is local and unpushed; neither candidate was deployed.

## Local resource-guard follow-up, 2026-10-01

The opt-in feed now has one process-local token bucket before JWT verification and body parsing: a burst of 60 requests, refilling one request per second. The normal app still returns 404 for the disabled feed. A dedicated HTTP test sends 100 unauthenticated requests with malformed JSON, observes 401 before exhaustion and 429 before parsing after it, and checks that health remains available. A second HTTP test injects a monotonic clock and checks no refill at 999 ms, one restored request at 1,000 ms, and a capped 60-request burst after 61 seconds. This guard bounds work in a single local app instance. It can be exhausted by another local caller and does not replace trusted-ingress or distributed per-client/tenant limits.

At this follow-up, `npm.cmd run build` and final `npm.cmd test` exited 0, with 69/69 tests. An intermediate full run passed 68/69: the original burst test assumed the bucket could not refill during real time, but a delayed request received 401 after a refill. The test now checks malformed requests inside the burst; the injected-clock test proves refill and burst capacity without sleeps. `gitleaks dir --no-banner --redact --exit-code 1 .` exited 0 with no findings in about 218 KB scanned. The first sandboxed `npm.cmd audit --omit=dev --audit-level=moderate` failed to reach npm's advisory endpoint; a network-approved retry with a workspace-local cache exited 0 and reported zero vulnerabilities. These local checks do not establish a live identity, accuracy, privacy, or hosted rollback boundary.
