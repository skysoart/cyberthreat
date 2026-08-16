# Adamantine — API Contract v1

**FROZEN.** Field names do not change without both frontend and backend agreeing.
Frontend builds against `frontend/mocks/*.json`. Backend builds to match this document.

- Base URL: `http://localhost:8000`
- All timestamps: ISO 8601 UTC, e.g. `2026-08-16T09:31:04Z`
- All `risk_score`: float, 0–100, one decimal
- All monetary/percentage-style floats: 0.0–1.0 unless stated
- Auth: dashboard endpoints are open in the demo. Sensor endpoints require
  `X-Adamantine-Key: adm_live_…`

## Naming (locked)

| | |
|---|---|
| Platform | **Adamantine** |
| Demo tenant | **Sample Store** (e-commerce) |
| Sensor script | `adamantine-sensor.js` |
| API key prefix | `adm_live_` |
| Incident IDs | `INC-0001` … |
| Playbook IDs | `PB-C-###` containment · `PB-E-###` eradication · `PB-R-###` recovery · `PB-H-###` hunt |
| Model versions | `v1.0.0` semver, patch bumps on retrain |

## Priority bands

`P1 ≥ 80` · `P2 ≥ 60` · `P3 ≥ 35` · `P4 < 35`

Colours (frontend may restyle, but keep the mapping):
`P1 #dc2626` · `P2 #ea580c` · `P3 #ca8a04` · `P4 #64748b`

## Attack classes (the 7 model outputs)

`normal` · `brute_force` · `credential_stuffing` · `dir_scan` · `flood` · `scraper` · `slow_recon`

## Asset inventory (Sample Store)

| asset_id | criticality | software |
|---|---|---|
| `payments-api` | 1.00 | Stripe SDK |
| `orders-db` | 0.95 | PostgreSQL 14 |
| `auth-service` | 0.90 | Node 20 |
| `admin-portal` | 0.85 | React |
| `checkout-web` | 0.80 | Next.js |
| `catalogue-api` | 0.50 | Spring Boot 2.5 ← Spring4Shell surface |
| `search-service` | 0.40 | Elasticsearch |
| `cdn-edge` | 0.30 | nginx 1.18 |
| `blog-cms` | 0.20 | WordPress 6.4 ← CVE surface |
| `metrics-agent` | 0.20 | Spring Boot Actuator |

---

# Endpoints

## `GET /api/v1/overview`
Dashboard home. Poll every 2s.

```json
{
  "tenant": "Sample Store",
  "window_days": 30,
  "counters": {
    "events_total": 52418,
    "events_last_24h": 3106,
    "incidents_open": 41,
    "incidents_p1": 6,
    "noise_reduction_pct": 99.9,
    "median_triage_seconds": 38
  },
  "trend": [
    { "date": "2026-07-18", "events": 1602, "incidents": 1 },
    { "date": "2026-07-19", "events": 1731, "incidents": 2 }
  ],
  "priority_split": { "P1": 6, "P2": 9, "P3": 14, "P4": 12 },
  "class_split": {
    "normal": 48912, "dir_scan": 1204, "credential_stuffing": 986,
    "scraper": 712, "brute_force": 341, "flood": 189, "slow_recon": 74
  },
  "top_sources": [
    { "asn": 14061, "asn_name": "DigitalOcean", "country": "NL",
      "events": 892, "is_hosting": true, "reputation_hit": false }
  ],
  "ticker": [
    { "ts": "2026-08-16T10:02:41Z", "src_ip": "185.220.101.34",
      "url_path": "/admin", "pred_class": "slow_recon",
      "pred_confidence": 0.91, "incident_id": "INC-0187" }
  ]
}
```

`ticker` returns the 25 most recent events. `trend` returns 30 entries.

---

## `GET /api/v1/incidents`
Query: `priority` (`P1`…`P4`), `status` (`open`|`confirmed`|`false_positive`|`closed`),
`limit` (default 50), `offset` (default 0). Sorted by `risk_score` descending.

```json
{
  "total": 41,
  "limit": 50,
  "offset": 0,
  "incidents": [
    {
      "id": "INC-0187",
      "title": "Multi-stage reconnaissance and credential attack",
      "status": "open",
      "priority": "P1",
      "risk_score": 82.7,
      "opened_at": "2026-08-16T09:14:22Z",
      "last_seen_at": "2026-08-16T10:02:41Z",
      "event_count": 9,
      "primary_class": "slow_recon",
      "kill_chain_depth": 3,
      "assets_affected": ["metrics-agent", "auth-service"],
      "users_affected": 3,
      "top_asn": 14061,
      "has_similar": true,
      "risk_breakdown": {
        "model_confidence":  { "raw": 0.94, "weight": 0.20, "points": 18.8 },
        "asset_criticality": { "raw": 0.90, "weight": 0.20, "points": 18.0 },
        "exploitability":    { "raw": 1.00, "weight": 0.20, "points": 20.0 },
        "blast_radius":      { "raw": 0.59, "weight": 0.15, "points": 8.8 },
        "kill_chain_depth":  { "raw": 0.50, "weight": 0.15, "points": 7.5 },
        "recency":           { "raw": 0.96, "weight": 0.10, "points": 9.6 }
      }
    }
  ]
}
```

> `risk_breakdown` keys are **fixed and ordered**. The stacked bar renders these six in this
> order. `points` always sums to `risk_score` (±0.1 rounding).

---

## `GET /api/v1/incidents/{id}`
Incident detail page. Everything the page needs, in one call.

```json
{
  "id": "INC-0187",
  "title": "Multi-stage reconnaissance and credential attack",
  "status": "open",
  "priority": "P1",
  "risk_score": 82.7,
  "opened_at": "2026-08-16T09:14:22Z",
  "last_seen_at": "2026-08-16T10:02:41Z",
  "risk_breakdown": { "…as above…" },

  "summary": "Nine events over 48 minutes from ASN 14061 (DigitalOcean). Individually all scored P4. Correlated, they form a reconnaissance campaign that identified a Spring Boot Actuator endpoint on metrics-agent, followed by credential stuffing against auth-service and one successful authentication.",

  "kill_chain": [
    { "tactic": "Reconnaissance", "technique_id": "T1595.002",
      "technique": "Vulnerability Scanning",
      "first_seen": "2026-08-16T09:14:22Z", "event_count": 5 },
    { "tactic": "Credential Access", "technique_id": "T1110.004",
      "technique": "Credential Stuffing",
      "first_seen": "2026-08-16T09:51:08Z", "event_count": 3 },
    { "tactic": "Initial Access", "technique_id": "T1078",
      "technique": "Valid Accounts",
      "first_seen": "2026-08-16T10:02:41Z", "event_count": 1 }
  ],

  "entities": [
    { "kind": "ip",     "value": "185.220.101.34", "event_count": 6, "reputation_hit": false },
    { "kind": "ip",     "value": "185.220.101.61", "event_count": 3, "reputation_hit": false },
    { "kind": "subnet", "value": "185.220.101.0/24", "event_count": 9 },
    { "kind": "asn",    "value": "14061", "event_count": 9 },
    { "kind": "user",   "value": "u_8f2a1c", "event_count": 3 },
    { "kind": "asset",  "value": "metrics-agent", "event_count": 5 },
    { "kind": "asset",  "value": "auth-service", "event_count": 4 },
    { "kind": "cve",    "value": "CVE-2022-22965", "event_count": 2 }
  ],

  "entity_graph_svg": "<svg viewBox=\"0 0 640 360\" xmlns=\"http://www.w3.org/2000/svg\">…</svg>",

  "threat_intel": [
    { "kind": "cve", "value": "CVE-2022-22965", "name": "Spring4Shell",
      "in_kev": true, "kev_added": "2022-04-04", "epss": 0.974,
      "matched_asset": "metrics-agent", "matched_software": "Spring Boot Actuator",
      "triggered_by_path": "/actuator/env", "source": "CISA KEV" }
  ],

  "similar_incident": {
    "id": "INC-0142",
    "similarity": 0.87,
    "opened_at": "2026-07-23T02:11:00Z",
    "days_ago": 24,
    "verdict": "confirmed_malicious",
    "shared": ["ASN 14061", "T1595.002", "T1110.004", "low_and_slow timing"]
  },

  "events": [
    {
      "id": 41822,
      "ts": "2026-08-16T09:14:22Z",
      "src_ip": "185.220.101.34",
      "url_path": "/.env",
      "http_status": 404,
      "user_id": null,
      "asset_id": "cdn-edge",
      "pred_class": "slow_recon",
      "pred_confidence": 0.71,
      "individual_priority": "P4",
      "attack_technique": "T1595.002",
      "evidence": [
        { "feature": "browser_telemetry_present", "value": 0,
          "baseline": "1", "deviation": "absent",
          "note": "no JavaScript executed — request did not come from a browser" },
        { "feature": "sensitive_path_hit", "value": 1,
          "baseline": "0", "deviation": "present",
          "note": "requested a credentials file path" },
        { "feature": "asn_is_hosting", "value": 1,
          "baseline": "0", "deviation": "present",
          "note": "datacentre origin, not residential" },
        { "feature": "interarrival_std_ms", "value": 3.1,
          "baseline": "800–4000", "deviation": "258× below baseline",
          "note": "machine-uniform request timing" }
      ]
    }
  ],

  "recommendations": {
    "containment": [
      { "id": "PB-C-011", "action": "Block ASN 14061 at WAF, 30-minute TTL",
        "owner": "Network Ops", "eta_min": 5,
        "rollback": "Remove ASN rule; verify legitimate traffic restored" },
      { "id": "PB-C-024", "action": "Force password reset for 3 targeted accounts",
        "owner": "IAM", "eta_min": 10, "rollback": "N/A — safe-forward" }
    ],
    "eradication": [
      { "id": "PB-E-007", "action": "Revoke all active sessions for affected users",
        "owner": "IAM", "eta_min": 2, "rollback": "N/A" }
    ],
    "recovery": [
      { "id": "PB-R-003", "action": "Patch metrics-agent to Spring Boot 2.6.6+ (CVE-2022-22965)",
        "owner": "Platform", "eta_min": 60, "rollback": "Redeploy previous image tag" }
    ],
    "hunt": [
      { "id": "PB-H-002", "action": "Search all authentication events from ASN 14061, last 30 days",
        "owner": "SOC", "eta_min": 15,
        "query": "SELECT * FROM events WHERE asn=14061 AND ts > now()-interval '30 days'" }
    ]
  },

  "narrative": "This incident began as low-volume reconnaissance…"
}
```

> **`individual_priority` on each event is the point of the whole product.** The detail page must
> show it next to the incident's `priority` so the P4 → P1 inversion is visible on screen.

---

## `POST /api/v1/incidents/{id}/feedback`

```json
{ "label": "false_positive", "analyst": "demo", "note": "optional" }
```
`label` ∈ `confirmed_threat` | `false_positive` | `reclassify`
(`reclassify` additionally requires `"new_class": "<attack class>"`)

Response: `{ "ok": true, "incident_id": "INC-0187", "new_status": "false_positive", "labels_pending": 12 }`

---

## `GET /api/v1/model`

```json
{
  "current": {
    "version": "v1.0.3", "trained_at": "2026-08-16T08:00:00Z",
    "n_base": 118402, "n_feedback": 47,
    "precision": 0.968, "recall": 0.941, "f1": 0.954,
    "pr_auc": 0.981, "fpr_at_90_recall": 0.012
  },
  "confusion_matrix": {
    "labels": ["normal","brute_force","credential_stuffing","dir_scan","flood","scraper","slow_recon"],
    "matrix": [[9812,3,11,7,0,22,14]]
  },
  "history": [
    { "version": "v1.0.3", "trained_at": "2026-08-16T08:00:00Z", "pr_auc": 0.981,
      "fpr_at_90_recall": 0.012, "promoted": true, "rejection_reason": null, "n_feedback": 47 },
    { "version": "v1.0.2-candidate", "trained_at": "2026-08-15T22:14:00Z", "pr_auc": 0.964,
      "fpr_at_90_recall": 0.019, "promoted": false,
      "rejection_reason": "FPR at 90% recall regressed 58% (0.012 → 0.019); gate requires ≤ 5%",
      "n_feedback": 31 }
  ],
  "feature_importance": [
    { "feature": "browser_telemetry_present", "importance": 0.184 },
    { "feature": "auth_fail_ip_60s", "importance": 0.142 },
    { "feature": "interarrival_std_ms", "importance": 0.121 }
  ]
}
```

> `history` **must** include rejected candidates. Showing a refused update is a stronger demo than
> showing only successes.

---

## `POST /api/v1/model/retrain`
Synchronous, ~3s.

```json
{
  "candidate_version": "v1.0.4",
  "promoted": true,
  "rejection_reason": null,
  "before": { "pr_auc": 0.981, "fpr_at_90_recall": 0.012 },
  "after":  { "pr_auc": 0.986, "fpr_at_90_recall": 0.011 },
  "n_feedback_used": 48,
  "duration_ms": 2840
}
```

## `POST /api/v1/model/rollback`
Body `{ "version": "v1.0.2" }` → `{ "ok": true, "current_version": "v1.0.2" }`

---

## `GET /api/v1/review-queue`
Uncertainty-sampled events for labelling.

```json
{
  "total": 24,
  "items": [
    { "event_id": 41903, "ts": "2026-08-16T10:14:02Z", "src_ip": "203.0.113.7",
      "url_path": "/products?page=48", "pred_class": "scraper",
      "pred_confidence": 0.52, "uncertainty": 0.48, "sampled_by": "uncertainty",
      "evidence": [ "…same shape as incident events…" ] }
  ]
}
```
`sampled_by` ∈ `uncertainty` | `random`

---

## `GET /api/v1/settings/weights` · `PUT /api/v1/settings/weights`

```json
{
  "model_confidence": 0.20, "asset_criticality": 0.20, "exploitability": 0.20,
  "blast_radius": 0.15, "kill_chain_depth": 0.15, "recency": 0.10
}
```
PUT the same shape. Must sum to 1.0 (±0.001) or `400`. Response re-scores all open incidents:
`{ "ok": true, "incidents_rescored": 41 }`

---

## `GET /api/v1/metrics`

```json
{
  "funnel": { "events": 52418, "candidate_alerts": 3506, "incidents": 41, "actionable": 6 },
  "model": { "precision": 0.968, "recall": 0.941, "f1": 0.954, "pr_auc": 0.981 },
  "pr_curve": [ { "recall": 0.10, "precision": 0.999 }, { "recall": 0.20, "precision": 0.997 } ],
  "top_k_precision": [ { "k": 5, "precision": 1.0 }, { "k": 10, "precision": 0.9 } ],
  "triage": { "manual_estimate_seconds": 900, "adamantine_seconds": 38, "reduction_pct": 95.8 }
}
```

---

## `POST /api/v1/telemetry` — sensor only
Frontend does not call this. Documented so the sensor and backend agree.

```json
{
  "session_id": "s_9f21ac44",
  "page": "/checkout",
  "browser": {
    "mouse_move_count": 214, "mouse_path_entropy": 4.82,
    "keystroke_count": 38, "keystroke_interval_mean": 187.4, "keystroke_interval_std": 92.1,
    "form_fill_ms": 8421, "paste_events": 0, "click_count": 6,
    "time_to_first_click_ms": 1840, "scroll_events": 22, "page_dwell_ms": 31200,
    "focus_blur_count": 1, "screen_w": 1920, "screen_h": 1080,
    "tz_offset": -330, "hardware_concurrency": 8
  }
}
```
Headers: `X-Adamantine-Key: adm_live_…`
Response: `{ "ok": true }` — always 200, never blocks the host page.

> Keystroke **timings** only. Never keystroke values. Say this when asked about privacy.

---

# Rules for the frontend

1. **The frontend renders; it never decides.** No risk scores computed in JS, no client-side
   grouping, sorting by a field the API didn't send, or derived statistics. One source of truth.
2. **No new or renamed fields.** If something's missing, it gets added here first.
3. **`entity_graph_svg` is a server-rendered SVG string.** Insert it into a container. No graph library.
4. **Chart.js vendored to `frontend/static/vendor/chart.min.js`.** No CDN — the demo runs offline.
5. **Poll `GET /api/v1/overview` every 2s** on the home page. Other pages load on navigation.
6. **`USE_MOCKS` flag** in one place. `true` reads `frontend/mocks/*.json`, `false` hits the API.
   Nothing else in the codebase knows which mode it's in.

# Screens

| Screen | Endpoints |
|---|---|
| Overview | `GET /overview` (2s poll) |
| Incident queue | `GET /incidents` |
| Incident detail | `GET /incidents/{id}`, `POST /incidents/{id}/feedback` |
| Model | `GET /model`, `POST /model/retrain`, `POST /model/rollback`, `GET /review-queue` |
| Metrics | `GET /metrics` |
| Settings | `GET/PUT /settings/weights` |
