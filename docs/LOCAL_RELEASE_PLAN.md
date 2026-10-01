# Local release and production gate plan

## Goal

Prove that this synthetic detector can be started and rolled back on loopback without exposing its unauthenticated analysis API. Keep production use blocked until identity, data, and accuracy evidence exists.

## Current state

At the start of this work, draft PR #17 was at `0e6bcee`. The app bound `127.0.0.1`, used fictional fixtures and a request-local label transform, and had no authentication, tenant model, live feed, or production deployment configuration. The previous reviewed commit is the rollback candidate; `origin/main` is not a safe rollback target because it binds on all interfaces and logs HTTP requests.

## Scope

- Add a request-level direct-loopback boundary and reject proxy/foreign-origin requests before JSON parsing.
- Refuse `NODE_ENV=production` startup while authentication and tenant controls are absent.
- Test the boundary and rehearse candidate-to-reviewed-commit rollback locally with synthetic data.
- Record the evidence still required for field accuracy and a production deployment.

No live feed, real employee/payload data, identity provider, production credential, merger, or public deployment is in scope.

## Acceptance criteria

1. Direct loopback health and synthetic fixture routes work.
2. Foreign Host, forwarded proxy, and cross-origin requests receive `403` without response data.
3. Production startup refuses to listen.
4. Build, test suite, and dependency audit pass at the changed head.
5. A local process using the candidate artifact can be replaced at the same loopback address by the previous reviewed artifact, and the prior artifact's health route responds.

## Risks and release class

This work is an R0 local-only demonstration. Exposing the analysis API with real traffic would be R3 or R4, depending on data and enforcement. The principal risks are accidental network exposure, raw payload intake, false findings, and an unsafe rollback to `main`.

## Design

Require an exact local Host header, a loopback socket peer, no forwarding headers, and a same-origin Origin if one is present. Check this before body parsing. Keep the existing `127.0.0.1` listen address and reject production startup. This is a containment measure, not an authentication or tenant design.

## Execution sequence

1. Modify `src/index.ts` and add `src/config/local-boundary.ts`.
2. Add HTTP boundary tests in `tests/api.test.ts`.
3. Run build, tests, audits, and a local candidate/rollback drill.
4. Review the final diff and update this plan and `README.md` with the evidence.

## Verification

Run `npm.cmd run build`, `npm.cmd test`, `npm.cmd audit --omit=dev --audit-level=moderate`, and a synthetic local release drill. A green synthetic challenge set is only a regression check; it is not a field accuracy estimate.

## Deployment and rollback

The supported target is a direct local loopback process only. `npm.cmd start` serves the compiled candidate. The drill uses a separate archive of the prior reviewed commit as a local rollback artifact, not `origin/main`. A production deploy command, URL, health check, and rollback target remain undefined and therefore blocked.

## Progress

- [x] Inspected source, tests, draft PR baseline, and release configuration.
- [x] Added local request and production-start boundaries.
- [x] Completed the local verification and candidate-to-prior-reviewed-commit rollback drill.
- [x] Recorded the remaining production gates in `PRODUCTION_EVIDENCE.md`.

## Decisions

- Do not promote `origin/main` as a rollback artifact.
- Do not add a demo token that could be mistaken for production authentication.

## Outcome (observed 2026-10-01)

The implementation commit was `10666152bbc1cda1a47ebd17f290e3214722f99e`. On Node 24 locally, `npm.cmd run build` exited 0, `npm.cmd test` passed 56/56, and `npm.cmd audit --omit=dev --audit-level=moderate` reported zero vulnerabilities. `gitleaks dir --no-banner --redact --exit-code 1 .` reported no findings; this single method does not establish a comprehensive clean audit. An actual `NODE_ENV=production` start exited 1 before listening with the expected refusal.

The initial `pwsh -NoProfile -File scripts/local-release-drill.ps1` success used candidate commit `10666152bbc1cda1a47ebd17f290e3214722f99e` and loopback port 61880. After correcting the drill to build the candidate itself, the same command exited 0 at later commit `bcd2f15d945c8d9dafc7875b81d4b67e4b782d77` on port 49678. That run built the candidate and an offline archived copy of previous reviewed PR commit `0e6bcee07a7d5415dc8f69929269dfa3dd65cdb0`, received health and `synthetic-demo` fixture responses from the candidate, stopped it, then received those responses from the previous commit at the same address. The previous commit is a local drill artifact, not a production rollback artifact. No public system was touched.

At `bcd2f15d945c8d9dafc7875b81d4b67e4b782d77`, GitHub's Node 20, Node 22, and CodeQL checks succeeded. These are dated observations, not a claim about a later PR head; check draft PR #17's live head and checks before a release decision. Production remains blocked by absent authenticated tenant-scoped ingestion, permissioned field data and labels, an approved retention and incident design, production observability, and a target-specific deployment and rollback exercise.
