# Adamantine — Project State

**Handoff document.** Read this first in a new session. Updated 2026-08-18.

---

## What this is

AI-powered cyber threat intelligence platform. Graded university project (VITISH'26 / SIH
internal, PS ID 29), judged with cross-questioning. The problem statement asks for three things:
**correlate** cyber events, **prioritise** incidents, **recommend** response actions.

**The thesis:** the same nine events score P4 individually and P1 correlated — not because
anything was reclassified, but because three of the six risk terms (blast radius, kill-chain
depth, asset spread) cannot be computed for a single event.

**Verified end to end, 31/31 checks passing:**

```
56,519 events  ->  6 incidents  ->  3 that matter   (99.99% reduction)

INC-0006  Multi-stage reconnaissance and credential attack
risk 84.5 · P1 · 9 events · 3 ATT&CK tactics
  model_confidence   0.86 × 0.20 = 17.3
  asset_criticality  0.90 × 0.20 = 18.0
  exploitability     1.00 × 0.20 = 20.0   ← CVE-2022-22965, live CISA KEV
  blast_radius       0.68 × 0.15 = 10.2
  kill_chain_depth   0.80 × 0.15 = 12.0
  recency            0.69 × 0.10 =  6.9
```

Not one event in the database scores above P3 individually. Correlation recovers **exactly the
six planted campaigns** — nothing fragmented, nothing over-merged.

---

## Locked decisions — do not relitigate

| | |
|---|---|
| **No LLM anywhere** | User constraint. Makes the no-hallucination answer stronger, not weaker. |
| **No XGBoost/LightGBM** | `sklearn.HistGradientBoostingClassifier`. |
| **No embeddings / PyTorch** | Correlation is entity + time based, not semantic. |
| **No JA3/JA4 fingerprinting** | uvicorn terminates TLS. Not obtainable. Suggested 3× now — refuse it. |
| **Localhost only, never Vercel** | Serverless breaks in-memory rate deques and SQLite. |
| **SQLAlchemy, not SQLModel** | Team 1's choice; intelligence layer adapted to it. |
| **Vanilla HTML/JS frontend** | Done. Do not rewrite. |
| Platform **Adamantine** · demo site **Sample Store** (e-commerce, INR) |

---

## Run it

```bash
pip install fastapi "uvicorn[standard]" sqlalchemy pydantic-settings passlib "bcrypt<4.1" email-validator pandas numpy scikit-learn joblib networkx pyyaml httpx jinja2 python-multipart
python -m backend.scripts.seed
python backend/scripts/fetch_feeds.py
python backend/scripts/verify_intelligence.py
```

Then the live suite, which needs a running server:

```bash
python -m uvicorn backend.app.main:app --port 8000
```

```bash
python backend/scripts/verify_live.py
```

**31/31 seeded + 21/21 live.** If **"correlation created P1 incidents from a table with none"**
fails, nothing else matters — that check *is* the project.

> `bcrypt<4.1` is required. passlib 1.7.4 crashes against bcrypt ≥ 4.1 with
> "password cannot be longer than 72 bytes" during its own capability probe.
> `email-validator` is required by the pydantic `EmailStr` in `schemas.py`.

Dashboard at `http://localhost:8000/frontend/index.html`, store at `http://localhost:8000/`.
Set `USE_MOCKS = false` in `frontend/static/api.js` — the API is real now.

### Live demo sequence

1. Browse the store, log in as `alice@samplestore.test` / `demo1234` — real human telemetry
2. Drive attacks by hand, or run `verify_live.py`
3. Correlation runs on a 15s timer (`CORRELATE_INTERVAL_SECONDS`), or `POST /api/v1/correlate`
4. Watch the incident appear in the queue

Manually driven attacks produce a genuine 5-tactic kill chain:
`Reconnaissance → Initial Access → Credential Access → Impact → Persistence`, risk 96.8, P1.

---

## Status

### Working
- `frontend/` — 6 dashboard screens, `static/api.js` mock layer, vendored Chart.js
- `demo-site/` — Sample Store, 600 generated products, 50 pages
- `backend/app/` — `main.py`, `middleware.py`, `counters.py`, `database.py`, `api/{store,telemetry,dashboard}.py`, real login + registration (Team 1)
- `backend/app/models/` — `tables.py` (Team 1), `constants.py` + `security_tables.py` (Team 2)
- `backend/app/services/` — `enrich`, `correlate`, `prioritize`, `recommend`, `engine` (Team 2)
- `backend/app/data/` — `assets.csv`, `path_cve_map.yaml`, `attack_map.yaml`, `playbooks.yaml`
- `backend/scripts/` — `seed.py`, `generate_events.py`, `attack_sim.py`, `fetch_feeds.py`, `verify_intelligence.py`
- Live threat intel: CISA KEV (1,666 CVEs), EPSS, Feodo. Tor list endpoint refused; degrades gracefully.

### Live path — working end to end

- `services/detect.py` — session fusion, rule-based classification, evidence, technique assignment
- `middleware.py` — fuses browser telemetry, resolves asset, classifies and scores every request
- `api/dashboard.py` — all routes call `ThreatEngine`; the mock fallback is **gone** on purpose,
  so a broken endpoint fails loudly instead of quietly serving fixtures
- `main.py` — daemon thread re-correlates every 15s
- Registration and login genuinely work; new accounts can be created and used

### Model — built and promoted

`backend/ml/train.py`, run with `python -m backend.ml.train`:

```
version v1.0.0 · promoted · trained in 43s · holdout 13,791
precision (macro) 1.000 · recall (macro) 0.933 · f1 0.960
PR-AUC (attack) 1.0 · FPR @ 90% recall 0.0
```

- Grouped split by session, or by source IP within a 10-minute bucket. Never random — requests
  inside one burst are near duplicates and would leak across the boundary.
- Isotonic calibration, so `pred_confidence` is a real probability. The risk formula multiplies
  by it, so a miscalibrated score corrupts every downstream priority.
- Frozen holdout, ids written to `ml/artifacts/holdout_ids.json` and reused forever. A gate
  measured against a moving target is not a gate.
- Promotion gate: PR-AUC must not decrease and FPR at 90% recall must not rise more than 5%.
  Rejected candidates are recorded with their reason and shown in the UI.
- `retrain_with_feedback()` trains on **human labels only**, and marks them consumed only if the
  candidate is actually promoted, so a rejection does not burn the analyst's work.

> **Be honest about PR-AUC 1.0.** The synthetic dataset is binary-separable: attack and benign
> traffic come from disjoint generators. It is an upper bound, not a generalisation estimate.
> The macro recall of 0.933 and the visible confusion between `credential_stuffing` and `normal`
> are the more meaningful numbers. Do not engineer the data further to make PR-AUC look worse —
> that is fitting the data to the metric. State the limitation instead.

### Sensor — built

`widget/adamantine-sensor.js`, served at `/adamantine-sensor.js`. Collects all 16 browser
features, POSTs to `/api/v1/telemetry` on a timer and on unload, and never breaks the host page.
Records keystroke **timings only** — key identities are never read, which is the privacy answer.

### Outstanding

Nothing blocking. Optional polish only: `top_k_precision` in the metrics payload is still an
empty list, and the Tor exit feed endpoint refused the connection (enrichment degrades fine).

### No email OTP — deliberate

Rejected: it needs an SMTP provider, which means an outbound dependency and the project's first
stored secret, both of which break the offline-on-localhost property. It also serves none of the
three graded verbs. Registration *abuse* is detected instead — automated signups map to
**T1136 Create Account** and show up in the kill chain, which is the security value without the
failure mode.

### Dead files — safe to delete (Team 1's call)
`backend/app/routes/` (superseded by `api/`) · `backend/app/models.py` (superseded by
`models/tables.py`) · `backend/app/config.py` (superseded by `core/config.py`).
`main.py` imports the `api/` and `models/tables.py` versions.

---

## Gotchas that cost real time

1. **`MAX_COMPONENT` + Louvain shredded the flood.** Community detection ran on any cluster over
   250 events, turning one 4,175-request flood from a single IP into 69 "incidents". Louvain is
   for breaking up spurious merges across *many* actors — it now only runs when a component has
   more than 3 distinct source IPs.
2. **High-fanout entities were skipped outright**, so that same flood produced *no* incident at
   all. Large buckets now chain-link adjacent-in-time events.
3. **Campaign matching was firing on 72 of 76 incidents.** The 24-bin hour histogram dominated
   the fingerprint vector. Threshold raised to 0.88 and a shared-technique requirement added;
   now exactly 1 match, which is what makes "87% similar" mean anything.
4. **Never floor `risk_score`.** `points` must sum to `risk_score` or the stacked bar lies.
   Fix the term curve instead.
5. **Kill-chain depth is a step curve**, not `depth / 9`.
6. **Browser features absent → `None`, never `0`.** Unknown is not zero.
7. **`cpe_product` must be a bare token** (`spring_framework`), not a CPE URI. `enrich.py`
   compares it exactly against `product:` in `path_cve_map.yaml`. A URI fails silently and costs
   17 points on the demo incident.
8. **`/login`, `/register`, `/checkout` were in `_SENSITIVE_PATHS`.** Those are ordinary store
   pages, so every successful login scored `sensitive_path_hit=1` with HTTP 200 and got labelled
   **T1190 Exploit Public-Facing Application** — a customer signing in appeared in the kill chain
   as an intrusion. That list is for config/secret paths only.
9. **`auth_success_after_fail` was never cleared**, so every request from an address claimed
   T1078 Valid Accounts forever after one successful login. It is a one-shot flag describing a
   single event, not a property of the address.
10. **A technique stored on the event wins over one recomputed during correlation.** `detect.py`
    assigns it while holding the actual request and knows the URL path; correlation is
    reconstructing from features alone and cannot.
11. **PowerShell 5.1 has no `&&`.** Use `;`. `git -C <path>` avoids `cd`.
12. Don't name a scratch script `inspect.py` — it shadows the stdlib module.

---

## Honest limitations (say these before a judge asks)

- **Training traffic is entirely synthetic.** Threat intel (KEV, EPSS, Feodo, ATT&CK) is real;
  traffic and labels are not. Treat any F1 as an upper bound.
- Correlation does **not** learn from data — deterministic over entities, time and real CVEs.
  Synthetic data limits the classifier's credibility, not the product's.
- Residential proxy rotation defeats the correlation architecture, not just the model.
  Retraining cannot fix that.
- `slow_recon` will have the worst per-event recall. That is the *argument for* correlation.
- SQLite + in-process rate counters won't scale. Postgres + Redis are the replacements.
- The system **recommends**; it never auto-executes. Automated blocking on a false positive
  takes your own site down.

---

## Deck

`docs/deck-content.md` — 15 slides. Numbers marked ⬛ final / 🟨 fill-after-build. Update the
headline to **56,519 → 6 → 3, 99.99%**. Only the model metrics (slide 13) remain unknown.

PPT review notes from 2026-08-18: template forbids paragraphs (slides 2/4/5/6 violate it);
"HighGradientBoostingClassifier" is misspelled — it's **Hist**; PS title, theme and "proof of
past work" are blank; add MITRE ATT&CK / CISA KEV / EPSS / networkx to the tech stack and
references.
