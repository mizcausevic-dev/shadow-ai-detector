# Production evidence still required

This repository supports a local synthetic demonstration only. Its public draft PR and green automated checks cannot authorize real ingestion or egress enforcement.

## Identity and tenant boundary

The candidate feed boundary at `/api/feed/:resourceId/analyze/payload`, `/event`, and `/traffic` is disabled in normal startup and is exercised only by an injected local test app. It verifies a pinned Ed25519 public key, exact issuer and audience, `at+jwt` type, expiry, age, `shadow:feed:analyze` scope, active-token status, server-owned tenant ownership, and a grant for the signed `client_id` and exact resource. It denies malformed, revoked, wrong-tenant, ungranted, or registry-failure requests before parsing their bodies. The configured test app does not mount the public fixture analysis or dashboard routes. `NODE_ENV=production` still refuses startup.

Before any reachable service is considered, choose a trusted identity provider and explicit tenant ownership. Confirm that its signed access tokens carry a trustworthy `client_id` and tenant claim; configure and test its keys, active-token/revocation source, resource and grant registries, credential lifetime, access grant process, and cross-tenant and ungranted-resource denials at the deployed boundary. No provider, credentials, tenant registry, or permission grants are configured here. The current loopback and explicit fixture opt-in restriction is containment, not a production identity boundary. The opt-in feed has a shared, process-local 60-request burst quota before JWT verification; it refills at one request per second. This is a local resource guard, not a per-client or distributed production quota. A local caller can exhaust it for all clients. A same-host proxy that rewrites headers can still expose the local app.

## Data and privacy boundary

Obtain an authorized feed contract describing fields, purpose, minimization, retention, deletion, access, audit logging, and incident escalation. Decide whether raw payloads are needed at all. Do not send real prompts, employee identities, keys, or network logs to this demo. The synthetic fixture and caller-supplied analysis routes do not retain data intentionally, but that is not a production privacy assessment.

## Detection acceptance

The hand-labeled synthetic challenge set contains 13 endpoint and 17 payload examples. It includes known positives and negatives and guards known regressions; it cannot estimate field precision, recall, missed destinations, or false alerts. For a permissioned pilot, freeze detector and catalog versions, label a representative sample independently, stratify by destination, payload category, department, and time period, and report TP/FP/FN/TN with confidence intervals and review cost. Include lookalike hosts, URL parser variants, noisy identifiers, and obfuscated sensitive strings. The owner must set thresholds and escalation policy before seeing pilot outcomes. Do not claim accurate detection from a passing synthetic suite.

## Operational gates

There is no live feed connector, per-tenant policy store, authenticated incident workflow, enforcement interface, production monitoring, backup, or production rollback artifact. A loopback rollback drill proves only the local artifact swap. A production release needs a concrete target, environment configuration, health and alert checks, permissioned synthetic smoke data, and an observed rollback on that target.
