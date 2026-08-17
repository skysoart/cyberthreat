# Adamantine — Backend Contract

**FROZEN.** Shared between Team 1 (Platform) and Team 2 (Intelligence). Nothing in this document
changes without both teams agreeing. Companion to `docs/api-contract.md`, which governs the
frontend seam.

Every identifier below is **exact**. Not "roughly this" — the literal string. A renamed feature or a
changed class label silently breaks the pipeline with no error message.

---

## 1. Ownership

| Path | Owner | Notes |
|---|---|---|
| `backend/app/models/tables.py` | **Neither team** | Schema. Ask before changing. |
| `backend/scripts/seed.py` | **Neither team** | Team 2's day-one input. |
| `backend/app/main.py`, `api/`, `core/` | Team 1 | |
| `widget/adamantine-sensor.js` | Team 1 | |
| `backend/app/middleware.py` | Team 1 | |
| `backend/scripts/attack_sim.py` | Team 1 | |
| `backend/ml/` | Team 2 | |
| `backend/app/services/` | Team 2 | |
| `backend/app/data/*.yaml`, `assets.csv` | Team 2 | |
| `frontend/`, `demo-site/` | **Neither** | Done. Do not edit. |

Rule: if you need something from the other team's file, ask them to add it. Do not edit across the
line.

---

## 2. Repo layout

```
backend/
├── app/
│   ├── main.py                 Team 1 — app, CORS, static mounts, router include
│   ├── middleware.py           Team 1 — server feature extraction
│   ├── core/config.py          Team 1 — settings, env vars
│   ├── models/tables.py        SHARED — schema
│   ├── api/
│   │   ├── telemetry.py        Team 1 — POST /api/v1/telemetry
│   │   ├── store.py            Team 1 — POST /login, demo-site routes
│   │   └── dashboard.py        Team 1 — all /api/v1/* dashboard endpoints
│   ├── services/
│   │   ├── engine.py           Team 2 — ThreatEngine (the seam)
│   │   ├── enrich.py           Team 2
│   │   ├── detect.py           Team 2
│   │   ├── correlate.py        Team 2
│   │   ├── prioritize.py       Team 2
│   │   └── recommend.py        Team 2
│   └── data/
│       ├── assets.csv          Team 2
│       ├── path_cve_map.yaml   Team 2
│       ├── attack_map.yaml     Team 2
│       ├── playbooks.yaml      Team 2
│       └── feeds/              Team 2 — cached, gitignored
├── ml/
│   ├── features.py             Team 2 — FEATURE_NAMES lives here
│   ├── train.py                Team 2
│   ├── evaluate.py             Team 2
│   └── artifacts/              gitignored
└── scripts/
    ├── seed.py                 SHARED
    ├── attack_sim.py           Team 1
    └── fetch_feeds.py          Team 2

widget/adamantine-sensor.js     Team 1
adamantine.db                   gitignored
```

---

## 3. The `Event` schema — the seam

Team 1 writes rows. Team 2 reads them. Nothing else crosses.

```python
class Event(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    tenant_id: str = "sample-store"
    ts: datetime                      # UTC, timezone-aware
    session_id: str | None            # s_<8 hex>  — None for direct API hits
    source: str                       # see SOURCES

    src_ip: str
    asn: int | None
    country: str | None               # ISO-3166 alpha-2
    user_id: str | None               # u_<6 hex>, hashed
    asset_id: str | None              # must match a row in assets.csv
    url_path: str
    http_status: int

    raw_json: str                     # original payload, JSON string
    features_json: str                # dict of the 47 features, JSON string

    # Written by Team 2 (null on insert)
    pred_class: str | None
    pred_confidence: float | None
    evidence_json: str | None
    attack_technique: str | None      # ATT&CK ID, e.g. "T1110.004"
    individual_priority: str | None   # P1..P4
```

**Team 1 fills everything up to `features_json`. Team 2 fills the rest.** Team 1 never writes a
prediction; Team 2 never writes a raw field.

---

## 4. Feature names — the highest drift risk

Defined once, in `backend/ml/features.py`:

```python
FEATURE_NAMES = SERVER_FEATURES + BROWSER_FEATURES + FUSION_FEATURES   # 47 total
```

The middleware and the sensor must emit **these exact keys**. A typo produces a silently missing
feature, not an error.

### `SERVER_FEATURES` — 30, Team 1 middleware

```
req_rate_10s              req_rate_60s              req_rate_300s
auth_fail_ip_60s          auth_fail_user_60s        distinct_users_tried_60s
auth_success_after_fails
unique_paths_60s          p404_ratio_60s            path_entropy
sensitive_path_hit
interarrival_mean_ms      interarrival_std_ms
payload_bytes             payload_bytes_std         resp_bytes_60s
header_count              ua_missing                ua_known_tool
ua_entropy                accept_lang_missing       header_order_hash_known
asn_is_hosting            country_risk              ip_reputation_hit
is_tor_exit
session_age_s             requests_this_session     hour_of_day
is_off_hours
```

> **No TLS/JA3/JA4 fingerprinting.** uvicorn terminates TLS and does not expose the handshake.
> It is not obtainable in this stack — do not spend time on it.

Rate features use in-memory `collections.deque` keyed by IP. **Do not query the database for rate
math** — it will not keep up.

`ip_reputation_hit` and `is_tor_exit` read Team 2's cached feed files. Team 1 reads them; Team 2
populates them. If the files are absent, emit `0`.

### `BROWSER_FEATURES` — 16, Team 1 sensor

```
mouse_move_count          mouse_path_entropy
keystroke_count           keystroke_interval_mean   keystroke_interval_std
form_fill_ms              paste_events
click_count               time_to_first_click_ms
scroll_events             page_dwell_ms             focus_blur_count
screen_w                  screen_h
tz_offset                 hardware_concurrency
```

Absent (no sensor ran) → **all 16 are `None`**, not `0`. `HistGradientBoostingClassifier` handles
NaN natively; zeros would be a lie.

> **Never transmit keystroke values.** Timings only. This is the privacy answer.

### `FUSION_FEATURES` — 1

```
browser_telemetry_present     # 1 if sensor telemetry was fused, else 0
```

Highest-importance feature in the model. Set by Team 1 at fusion time.

---

## 5. Enumerations — exact strings

### `CLASSES` (7) — model output, `pred_class`
```
normal  brute_force  credential_stuffing  dir_scan  flood  scraper  slow_recon
```

### `SOURCES` — `Event.source`
```
widget  server  firewall  email_gw  edr
```
Only `widget` and `server` are produced live. The rest come from `seed.py`.

### Priority bands
```
P1 >= 80    P2 >= 60    P3 >= 35    P4 < 35
```
Applied identically to `Event.individual_priority` and `Incident.priority`.

### Entity kinds
```
ip  subnet  asn  user  ua_hash  asset  session  cve
```

### Feedback labels
```
confirmed_threat  false_positive  reclassify
```

### Incident status
```
open  confirmed  false_positive  closed
```

---

## 6. `ThreatEngine` — the code seam

`backend/app/services/engine.py`. Team 2 writes it, Team 1 imports it. One instance, created at
startup.

```python
class ThreatEngine:
    def score_event(self, event_id: int) -> None:          # fills pred_* on the row
    def correlate(self) -> int:                            # returns incidents touched
    def get_overview(self) -> dict
    def get_incidents(self, priority=None, status=None, limit=50, offset=0) -> dict
    def get_incident(self, incident_id: str) -> dict
    def submit_feedback(self, incident_id: str, label: str, analyst: str, note=None) -> dict
    def get_model(self) -> dict
    def retrain(self) -> dict
    def rollback(self, version: str) -> dict
    def get_review_queue(self) -> dict
    def get_metrics(self) -> dict
    def get_weights(self) -> dict
    def set_weights(self, weights: dict) -> dict
```

> **Every `get_*` returns the response body from `docs/api-contract.md` verbatim.** Same keys, same
> nesting, same types. Team 1's route handlers are one line: call the method, return the dict. No
> reshaping in the API layer — if the shape is wrong, it is fixed in `engine.py`.

**Until `engine.py` exists**, Team 1's handlers read `frontend/mocks/*.json` from disk and return
them. Do this on day one — it lets the dashboard run against a real server immediately, with
`USE_MOCKS = false`.

---

## 7. Routes

### Sample Store — Team 1
```
GET  /                        demo-site/index.html
GET  /products                demo-site/products.html      (?page=1..50)
GET  /products/{id}           demo-site/product.html
GET  /cart /checkout /login /register /account /admin
POST /login                   JSON {email, password} -> 200 | 401
GET  /actuator/env            demo-site/actuator-env.json   ** MUST return 200 **
GET  /sitemap.xml  /robots.txt
GET  /.env  /.git/config  /wp-admin/  /phpmyadmin/   ** MUST return 404 **
GET  /adamantine-sensor.js    widget/adamantine-sensor.js
```

Test accounts, password `demo1234` for all:

| Email | `user_id` |
|---|---|
| `alice@samplestore.test` | `u_8f2a1c` |
| `bob@samplestore.test` | `u_3b71ef` |
| `carol@samplestore.test` | `u_c04d92` |

### API — Team 1
```
POST /api/v1/telemetry                   header X-Adamantine-Key: adm_live_demo
GET  /api/v1/overview
GET  /api/v1/incidents
GET  /api/v1/incidents/{id}
POST /api/v1/incidents/{id}/feedback
GET  /api/v1/model
POST /api/v1/model/retrain
POST /api/v1/model/rollback
GET  /api/v1/review-queue
GET  /api/v1/metrics
GET  /api/v1/settings/weights
PUT  /api/v1/settings/weights
```

CORS: allow `http://localhost:8000` only.

---

## 8. Conventions

| | |
|---|---|
| Timestamps | ISO 8601 UTC with `Z`. Store timezone-aware. |
| Session IDs | `s_` + 8 lowercase hex |
| User IDs | `u_` + 6 lowercase hex, hashed from email |
| Incident IDs | `INC-` + 4 digits, zero-padded |
| Playbook IDs | `PB-C-###` `PB-E-###` `PB-R-###` `PB-H-###` |
| Model versions | `v{major}.{minor}.{patch}`, patch bumps on retrain |
| Risk scores | float, 1 decimal, 0–100 |
| Confidences | float, 0.0–1.0 |
| ASN | integer, no `AS` prefix |
| Country | ISO-3166 alpha-2, uppercase |
| Money | none anywhere |

---

## 9. Config

`backend/app/core/config.py`, all overridable by env var:

```
DATABASE_URL      = "sqlite:///./adamantine.db"
API_KEY           = "adm_live_demo"
OFFLINE           = 0        # 1 blocks all outbound HTTP; feeds read cache only
MODEL_PATH        = "backend/ml/artifacts/current.joblib"
EDGE_CUT_THRESHOLD    = 0.9      # sum of edge weights below this -> no link
SIMILARITY_THRESHOLD  = 0.75     # historical campaign fingerprint match
MAX_CLUSTER_EVENTS    = 200      # above this, re-split with Louvain

# Correlation windows are PER ENTITY TYPE, not global. base_weight applies at
# zero time gap; the link expires past window_minutes.
CORRELATION_WINDOWS = {
    # entity kind   base_weight   window_minutes
    "session":      (1.0,   None),   # never expires
    "ip":           (1.0,   30),
    "user":         (0.8,   120),
    "subnet":       (0.7,   60),
    "ua_hash":      (0.6,   360),
    "asn":          (0.4,   360),
    "cve":          (0.5,   1440),
}
```

> **Roadmap, not v1:** decay each edge by `base_weight * exp(-gap_hours / tau)`
> rather than expiring it at a hard cutoff. That allows 24-hour windows on the
> weak links (`asn`, `ua_hash`) without merge bombs — a day-old ASN match then
> contributes ~0.1 and can tip a cluster only alongside other evidence, never on
> its own. Do not build this until basic correlation passes its acceptance test.

**No secrets in this project.** No LLM keys, no third-party accounts. If anyone adds a `.env`
requiring a credential, something has gone wrong.

---

## 10. Rules that will actually bite

1. **Feature names come from `ml/features.py` and nowhere else.** The sensor and middleware import
   or mirror that list. Never retype a feature name.
2. **Missing browser features are `None`, never `0`.**
3. **`/actuator/env` returns 200.** Every other probe path returns 404. This is the demo.
4. **Never train on model predictions.** Only human labels from the feedback table.
5. **Split by `session_id`, never by row**, when evaluating. `GroupShuffleSplit`. Row-wise splitting
   leaks near-duplicate requests and produces a fake 99.9%.
6. **Report PR-AUC and FPR at 90% recall.** Never accuracy alone — classes are ~1:50.
7. **Rate features from in-memory deques**, not SQL.
8. **All feeds cached to disk.** Nothing calls out during a demo. `OFFLINE=1` must work.
9. **Neither team edits `frontend/` or `demo-site/`.** They are finished.
10. **`ThreatEngine` returns contract shapes verbatim.** No reshaping in the API layer.

---

## 11. Day-one order

| Who | First thing |
|---|---|
| Shared | `models/tables.py`, then `scripts/seed.py` |
| Team 1 | FastAPI app serving `demo-site/` + dashboard endpoints returning mocks from disk |
| Team 2 | `ml/features.py` with `FEATURE_NAMES` frozen — everyone else depends on it |

Team 1 cannot write the sensor or middleware until `FEATURE_NAMES` exists. Team 2 cannot build
correlation until `seed.py` has populated the database. Those two files are the critical path;
everything else can start once they land.
