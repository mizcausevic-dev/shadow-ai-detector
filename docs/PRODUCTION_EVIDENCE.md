# Production evidence still required

This repository supports a local synthetic demonstration only. Its public draft PR and green automated checks cannot authorize real ingestion or egress enforcement.

## Identity and tenant boundary

Before any reachable service is considered, choose a trusted identity provider and explicit tenant ownership. The service must validate issuer, audience, signature, expiry, and requested scope; derive tenant from the verified identity rather than request data; reject cross-tenant reads and writes; and test those failures at the deployed boundary. No provider, credentials, tenant registry, or permission grants are configured here. The current loopback and explicit fixture opt-in restriction is containment, not authentication. A same-host proxy that rewrites headers can still expose this app.

## Data and privacy boundary

Obtain an authorized feed contract describing fields, purpose, minimization, retention, deletion, access, audit logging, and incident escalation. Decide whether raw payloads are needed at all. Do not send real prompts, employee identities, keys, or network logs to this demo. The synthetic fixture and caller-supplied analysis routes do not retain data intentionally, but that is not a production privacy assessment.

## Detection acceptance

The hand-labeled synthetic challenge set contains 13 endpoint and 17 payload examples. It includes known positives and negatives and guards known regressions; it cannot estimate field precision, recall, missed destinations, or false alerts. For a permissioned pilot, freeze detector and catalog versions, label a representative sample independently, stratify by destination, payload category, department, and time period, and report TP/FP/FN/TN with confidence intervals and review cost. Include lookalike hosts, URL parser variants, noisy identifiers, and obfuscated sensitive strings. The owner must set thresholds and escalation policy before seeing pilot outcomes. Do not claim accurate detection from a passing synthetic suite.

## Operational gates

There is no live feed connector, per-tenant policy store, authenticated incident workflow, enforcement interface, production monitoring, backup, or production rollback artifact. A loopback rollback drill proves only the local artifact swap. A production release needs a concrete target, environment configuration, health and alert checks, permissioned synthetic smoke data, and an observed rollback on that target.
