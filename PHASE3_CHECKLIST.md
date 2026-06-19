# Phase 3 — Security Intelligence Checklist

Scope: `NeoShield_Specification.md` §3.7 and §9 (Phase 3). Phase 3 is closed only
when the exit criteria below are demonstrable with real scan data.

Current status: **3.1 scores and 3.2 incidents are implemented and tested.**
3.3 remediation, 3.4 AI explanations and 3.5 reports are still open.

## Exit criteria (from the specification)

- [ ] Findings from GitHub, domains, Wazuh and Nmap flow through one intelligence layer.
- [ ] Scores are explainable (breakdown + algorithm version).
- [ ] Correlated incidents show evidence and their correlation rule.
- [ ] Remediation can be tracked and verified by a later successful scan.
- [ ] AI explanations are optional and the platform works without an API key.
- [ ] Demo steps 7–10 in the specification are reproducible.

## 3.1 Deterministic health scores

- [x] Document the scoring model: base points, exposure and criticality multipliers, cap.
- [x] Pure scoring module (`web/lib/intelligence/score.ts`) with algorithm version.
- [x] Deduplicate recurring instances: one finding row per `(asset, stableKey)` counts once.
- [x] Exclude non-open statuses (`resolved`, `accepted_risk`, `false_positive`).
- [x] Breakdown by severity, asset type and exposure.
- [x] `score_snapshot` table (workspace + project scope) for trends.
- [x] Snapshot only when the score/count changes or the newest snapshot is >24h old.
- [x] Overview health card with score, version, risk points and severity breakdown.
- [x] Project health card and score history sparkline.
- [x] Unit tests for the algorithm (`bun test`).
- [ ] Recompute on a schedule independent of page views (only lazy recompute today).

## 3.2 Deterministic incident correlation

- [x] `incident`, `incident_finding`, `incident_event` tables + enums.
- [x] Correlation engine (`web/lib/intelligence/correlation.ts`), pure and deterministic.
- [x] Rule: repeated endpoint authentication failures (24h window, occurrence count).
- [x] Rule: exposed SSH/RDP plus authentication failures on the same endpoint IP.
- [x] Rule: secret finding in a production project that explicitly owns domain assets.
- [x] Rule: three or more high/critical open findings on one asset (7-day window).
- [x] Rule: authentication event burst from one source IP against one asset (24h).
- [x] Every incident stores its rule id, correlation key, reason and evidence.
- [x] Incident links carry a per-finding association reason.
- [x] Incidents auto-resolve when their signal set disappears (system event + note).
- [ ] Reopen an auto-resolved incident automatically when its signals return.
- [x] Incident list + filters, detail page, timeline, related findings.
- [x] Status transitions (`new`, `investigating`, `contained`, `resolved`, `closed`) with history.
- [x] Investigation notes (members) and status changes (admins) are audited.
- [x] `GET /api/v1/incidents` and `GET/PATCH /api/v1/incidents/:incidentId`.
- [x] Unit tests for every rule, positive and negative.
- [ ] Incident-linked security events are shown individually on the timeline
      (today the events are referenced in evidence, not linked rows).

## 3.3 Finding lifecycle + remediation tracking (next)

- [ ] Write a `finding_status_event` when a resolved finding reopens on rediscovery.
- [ ] Optional owner/assignee on findings and incidents.
- [ ] Free-form finding notes (beyond status-change notes).
- [ ] `remediation` table: recommendation, status (`planned`, `in_progress`, `fixed`,
      `verified`), who/when/what history, verification scan reference.
- [ ] Later successful scan verifies a remediation; failed scans never verify.
- [ ] Remediation UI on finding and incident detail pages.
- [ ] Worker grants + migration for any table the Python worker writes.

## 3.4 Optional AI explanations

- [ ] Provider adapter (Gemini first) behind a server-side interface.
- [ ] Redaction allowlist: title, rule/CVE, package/version, file path, non-sensitive
      evidence and remediation references only.
- [ ] Never send secrets, tokens, private keys, credentials, env files or source code.
- [ ] "Explain with AI" action on findings and incidents; output clearly labeled and
      linked to its source finding/incident.
- [ ] No-key / quota-exhausted state; platform remains fully functional.
- [ ] AI cannot set severity, close findings or take actions.
- [ ] Store generated explanations with model, timestamp and input digest.
- [ ] Tests for the redaction boundary.

## 3.5 Project reports + trends

- [ ] Per-project report: score with provenance, severity/exposure breakdown, open
      findings, incidents, remediation history.
- [ ] Workspace score trend and finding trend over snapshots/scan runs.
- [ ] CSV and JSON export (PDF optional, not required).
- [ ] Report page replaces the `ComingSoon` placeholder.

## Cross-cutting

- [x] Overview shows open findings, health score, recent incidents and scan activity.
- [x] Authorization on every intelligence mutation; audit every user action.
- [ ] Loading, empty, success and failure states on every new screen.
- [x] README + `web/docs/architecture.md` updated for the intelligence layer.
- [x] Web unit tests wired into the pre-push check (`bun test`).
