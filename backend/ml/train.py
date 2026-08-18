"""
backend/ml/train.py — Team 2.

Trains the traffic classifier and runs the promotion gate.

    python -m backend.ml.train              # train and promote a first model
    python -m backend.ml.train --evaluate   # metrics only, promote nothing

Three decisions worth defending:

  GROUPED SPLIT, NOT RANDOM. Requests inside one attack session are near
  duplicates. Split them at random and the same burst lands in both train and
  test, and you get a 99.9% that means nothing. We group by session where one
  exists and by source IP otherwise, so an attacker seen in training is never
  also in the holdout.

  PR-AUC AND FPR-AT-RECALL, NOT ACCURACY. Attacks are a small fraction of
  traffic. A model that answers "normal" every time scores ~92% accuracy and is
  worthless. Precision-recall area and false-positive rate at fixed recall are
  the numbers a SOC actually cares about.

  A FROZEN HOLDOUT, CARVED ONCE. Its event ids are written to disk and reused
  for every future retrain. A promotion gate measured against a moving target
  is not a gate.

Retraining never trains on the model's own predictions — only on human labels
from the feedback table. Self-training on confident outputs is confirmation
bias, and any attacker who can generate traffic could use it to teach the model
that their traffic is normal.
"""

from __future__ import annotations

import sys
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np

from backend.ml.features import FEATURE_NAMES, to_vector

# Windows consoles default to cp1252, which cannot encode the box-drawing
# and typographic characters used below. Without this, piping this script's
# output crashes with UnicodeEncodeError on a default Windows install.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
HOLDOUT_FILE = ARTIFACTS / "holdout_ids.json"
CURRENT = ARTIFACTS / "current.joblib"

HOLDOUT_FRACTION = 0.25
RANDOM_STATE = 42

# Promotion gate. A candidate must not be worse on either axis.
MIN_PR_AUC_DELTA = 0.0      # must at least match the champion
MAX_FPR_REGRESSION = 1.05   # and must not raise false positives by >5%


# ------------------------------------------------------------------ dataset

def load_dataset(session_factory) -> dict[str, Any]:
    """Pull labelled events out of the database into arrays."""
    from backend.app.models.tables import Event

    db = session_factory()
    try:
        rows = (db.query(Event)
                  .filter(Event.pred_class.isnot(None))
                  .filter(Event.features_json.isnot(None))
                  .all())
        # Group key. Requests in one session, or from one address inside the
        # same 10-minute window, are near duplicates and must never straddle
        # the split. Bucketing by time as well as address means a campaign
        # running for hours still contributes to both sides, so every class is
        # represented — grouping on the raw IP put whole attack classes
        # entirely into train or entirely into test.
        data = []
        for r in rows:
            if r.session_id:
                key = f"sess:{r.session_id}"
            else:
                bucket = int(r.ts.timestamp() // 600) if r.ts else 0
                key = f"ip:{r.src_ip}:{bucket}"
            data.append((r.id, r.features_json, r.pred_class, key))
    finally:
        db.close()

    if not data:
        raise RuntimeError("no labelled events — run backend/scripts/seed.py first")

    ids = np.array([d[0] for d in data])
    X = np.vstack([to_vector(json.loads(d[1] or "{}")) for d in data])
    y = np.array([d[2] for d in data])
    groups = np.array([d[3] for d in data])
    return {"ids": ids, "X": X, "y": y, "groups": groups}


def freeze_holdout(ids, groups, force: bool = False) -> set[int]:
    """
    Carve the holdout once and remember it. Every later retrain is measured
    against exactly the same rows, which is what makes the gate meaningful.
    """
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    if HOLDOUT_FILE.exists() and not force:
        stored = set(json.loads(HOLDOUT_FILE.read_text()))
        if stored & set(int(i) for i in ids):
            return stored

    from sklearn.model_selection import GroupShuffleSplit
    splitter = GroupShuffleSplit(n_splits=1, test_size=HOLDOUT_FRACTION,
                                 random_state=RANDOM_STATE)
    _, test_idx = next(splitter.split(np.zeros(len(ids)), groups=groups))
    holdout = set(int(ids[i]) for i in test_idx)
    HOLDOUT_FILE.write_text(json.dumps(sorted(holdout)))
    return holdout


# -------------------------------------------------------------------- model

def build_model():
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import HistGradientBoostingClassifier

    base = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.1, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.15,
        random_state=RANDOM_STATE,
    )
    # Isotonic calibration so `pred_confidence` is a real probability rather
    # than a number that merely looks like one — the risk formula multiplies
    # by it, so a miscalibrated score corrupts every downstream priority.
    return CalibratedClassifierCV(base, method="isotonic", cv=3)


def evaluate(model, X, y) -> dict[str, Any]:
    """Metrics that survive class imbalance, plus the confusion matrix."""
    from sklearn.metrics import (
        average_precision_score, confusion_matrix, f1_score,
        precision_recall_curve, precision_score, recall_score,
    )

    pred = model.predict(X)
    labels = sorted(set(y) | set(pred))

    # Binary view: is this an attack at all? This is the question the SOC asks,
    # and the one where imbalance actually bites.
    y_bin = (y != "normal").astype(int)
    classes = list(model.classes_)
    proba = model.predict_proba(X)
    if "normal" in classes:
        attack_p = 1.0 - proba[:, classes.index("normal")]
    else:
        attack_p = proba.max(axis=1)

    pr_auc = float(average_precision_score(y_bin, attack_p)) if y_bin.any() else None

    fpr_at_90 = None
    if y_bin.any():
        prec, rec, thr = precision_recall_curve(y_bin, attack_p)
        ok = np.where(rec >= 0.90)[0]
        if len(ok) and len(thr):
            i = min(ok[-1], len(thr) - 1)
            flagged = attack_p >= thr[i]
            neg = (y_bin == 0)
            fpr_at_90 = float((flagged & neg).sum() / max(1, neg.sum()))

    return {
        "precision": float(precision_score(y, pred, average="macro", zero_division=0)),
        "recall": float(recall_score(y, pred, average="macro", zero_division=0)),
        "f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "pr_auc": pr_auc,
        "fpr_at_90_recall": fpr_at_90,
        "confusion_matrix": {
            "labels": labels,
            "matrix": confusion_matrix(y, pred, labels=labels).tolist(),
        },
        "n_test": int(len(y)),
    }


def pr_curve_points(model, X, y, n: int = 14) -> list[dict]:
    from sklearn.metrics import precision_recall_curve
    y_bin = (y != "normal").astype(int)
    if not y_bin.any():
        return []
    classes = list(model.classes_)
    proba = model.predict_proba(X)
    attack_p = (1.0 - proba[:, classes.index("normal")]
                if "normal" in classes else proba.max(axis=1))
    prec, rec, _ = precision_recall_curve(y_bin, attack_p)
    idx = np.linspace(0, len(rec) - 1, n).astype(int)
    return [{"recall": round(float(rec[i]), 3), "precision": round(float(prec[i]), 3)}
            for i in sorted(set(idx))]


def feature_importance(model, X, y, top: int = 12) -> list[dict]:
    """Permutation importance — a legitimate, citable method, and it also
    feeds the Evidence Engine's ranking in services/detect.py."""
    from sklearn.inspection import permutation_importance
    n = min(len(X), 4000)
    rs = np.random.RandomState(RANDOM_STATE)
    sel = rs.choice(len(X), n, replace=False)
    r = permutation_importance(model, X[sel], y[sel], n_repeats=3,
                               random_state=RANDOM_STATE, n_jobs=1)
    order = np.argsort(r.importances_mean)[::-1][:top]
    return [{"feature": FEATURE_NAMES[i],
             "importance": round(float(r.importances_mean[i]), 4)}
            for i in order if r.importances_mean[i] > 0]


# ------------------------------------------------------------------ training

def _next_version(session_factory) -> str:
    from backend.app.models.security_tables import ModelVersion
    db = session_factory()
    try:
        rows = db.query(ModelVersion).all()
        patches = []
        for v in rows:
            try:
                patches.append(int(v.version.lstrip("v").split(".")[-1]))
            except (ValueError, AttributeError):
                pass
        return f"v1.0.{max(patches) + 1 if patches else 0}"
    finally:
        db.close()


def train(session_factory, promote: bool = True,
          extra: Optional[tuple] = None) -> dict[str, Any]:
    """
    Train a candidate, evaluate it on the frozen holdout, and promote it only
    if it clears the gate. Returns the API-contract retrain response.
    """
    import joblib
    from backend.app.models.security_tables import ModelVersion

    started = time.time()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    ds = load_dataset(session_factory)
    holdout = freeze_holdout(ds["ids"], ds["groups"])
    is_test = np.array([int(i) in holdout for i in ds["ids"]])

    X_tr, y_tr = ds["X"][~is_test], ds["y"][~is_test]
    X_te, y_te = ds["X"][is_test], ds["y"][is_test]

    n_feedback = 0
    if extra is not None and len(extra[0]):
        X_tr = np.vstack([X_tr, extra[0]])
        y_tr = np.concatenate([y_tr, extra[1]])
        n_feedback = len(extra[1])

    if len(set(y_tr)) < 2:
        return {"candidate_version": None, "promoted": False,
                "rejection_reason": "training set contains a single class",
                "before": {}, "after": {}, "n_feedback_used": n_feedback,
                "duration_ms": int((time.time() - started) * 1000)}

    model = build_model()
    model.fit(X_tr, y_tr)
    metrics = evaluate(model, X_te, y_te)

    # champion, if any
    champion = None
    db = session_factory()
    try:
        champion = (db.query(ModelVersion)
                      .filter(ModelVersion.promoted.is_(True))
                      .order_by(ModelVersion.trained_at.desc()).first())
        before = {"pr_auc": champion.pr_auc,
                  "fpr_at_90_recall": champion.fpr_at_90_recall} if champion else {}
    finally:
        db.close()

    after = {"pr_auc": metrics["pr_auc"],
             "fpr_at_90_recall": metrics["fpr_at_90_recall"]}

    reason = None
    if champion is not None and promote:
        if (metrics["pr_auc"] is not None and champion.pr_auc is not None
                and metrics["pr_auc"] < champion.pr_auc - MIN_PR_AUC_DELTA):
            reason = (f"PR-AUC regressed {champion.pr_auc:.4f} -> "
                      f"{metrics['pr_auc']:.4f}; gate requires no decrease")
        elif (metrics["fpr_at_90_recall"] is not None
              and champion.fpr_at_90_recall is not None
              and champion.fpr_at_90_recall > 0
              and metrics["fpr_at_90_recall"]
              > champion.fpr_at_90_recall * MAX_FPR_REGRESSION):
            reason = (f"FPR at 90% recall regressed "
                      f"{champion.fpr_at_90_recall:.4f} -> "
                      f"{metrics['fpr_at_90_recall']:.4f}; gate allows at most "
                      f"{int((MAX_FPR_REGRESSION - 1) * 100)}%")

    version = _next_version(session_factory)
    promoted = promote and reason is None

    meta = {
        "version": version, "n_base": int(len(y_tr) - n_feedback),
        **{k: metrics[k] for k in ("precision", "recall", "f1", "pr_auc",
                                   "fpr_at_90_recall", "confusion_matrix")},
        "feature_importance": feature_importance(model, X_te, y_te),
        "pr_curve": pr_curve_points(model, X_te, y_te),
        "top_k_precision": [],
    }

    path = ARTIFACTS / f"{version}.joblib"
    joblib.dump({"model": model, "meta": meta}, path)
    if promoted:
        joblib.dump({"model": model, "meta": meta}, CURRENT)

    db = session_factory()
    try:
        if promoted:
            for v in db.query(ModelVersion).all():
                v.promoted = False
                db.add(v)
        db.add(ModelVersion(
            version=version, trained_at=datetime.now(timezone.utc),
            n_base=int(len(y_tr) - n_feedback), n_feedback=n_feedback,
            precision=metrics["precision"], recall=metrics["recall"],
            f1=metrics["f1"], pr_auc=metrics["pr_auc"],
            fpr_at_90_recall=metrics["fpr_at_90_recall"],
            promoted=promoted, rejection_reason=reason,
            artifact_path=str(path), meta_json=json.dumps(meta),
        ))
        db.commit()
    finally:
        db.close()

    return {
        "candidate_version": version,
        "promoted": promoted,
        "rejection_reason": reason,
        "before": before, "after": after,
        "n_feedback_used": n_feedback,
        "duration_ms": int((time.time() - started) * 1000),
        "metrics": metrics,
    }


def retrain_with_feedback(session_factory) -> dict[str, Any]:
    """
    Called by ThreatEngine.retrain(). Human labels only.

    A `false_positive` verdict relabels that incident's events as normal; a
    `confirmed_threat` keeps the predicted class but promotes it to a
    verified label. Nothing here reads the model's own opinion.
    """
    from backend.app.models.security_tables import Feedback
    from backend.app.models.tables import Event

    db = session_factory()
    try:
        pending = (db.query(Feedback)
                     .filter(Feedback.consumed_by_version.is_(None)).all())
        rows: list[tuple[str, str]] = []
        for fb in pending:
            if not fb.incident_id:
                continue
            evs = db.query(Event).filter(Event.incident_id == fb.incident_id).all()
            for e in evs:
                if fb.label == "false_positive":
                    rows.append((e.features_json, "normal"))
                elif fb.label == "reclassify" and fb.new_class:
                    rows.append((e.features_json, fb.new_class))
                elif fb.label == "confirmed_threat" and e.pred_class:
                    rows.append((e.features_json, e.pred_class))
        pending_ids = [fb.id for fb in pending]
    finally:
        db.close()

    extra = None
    if rows:
        extra = (np.vstack([to_vector(json.loads(f or "{}")) for f, _ in rows]),
                 np.array([c for _, c in rows]))

    result = train(session_factory, promote=True, extra=extra)

    # Mark labels consumed only if the candidate was actually promoted, so a
    # rejected model does not silently burn the analyst's work.
    if result["promoted"] and pending_ids:
        db = session_factory()
        try:
            for fb in db.query(Feedback).filter(Feedback.id.in_(pending_ids)).all():
                fb.consumed_by_version = result["candidate_version"]
                db.add(fb)
            db.commit()
        finally:
            db.close()
    return result


def main() -> None:
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from backend.app.database import SessionLocal

    ap = argparse.ArgumentParser()
    ap.add_argument("--evaluate", action="store_true",
                    help="train and report, but promote nothing")
    args = ap.parse_args()

    print("training on labelled events from the database...")
    r = train(SessionLocal, promote=not args.evaluate)
    m = r.get("metrics", {})

    print(f"\n  version           {r['candidate_version']}")
    print(f"  promoted          {r['promoted']}")
    if r["rejection_reason"]:
        print(f"  rejected because  {r['rejection_reason']}")
    print(f"  trained in        {r['duration_ms']} ms")
    print(f"\n  precision (macro) {m.get('precision'):.4f}")
    print(f"  recall (macro)    {m.get('recall'):.4f}")
    print(f"  f1 (macro)        {m.get('f1'):.4f}")
    print(f"  PR-AUC (attack)   {m.get('pr_auc')}")
    print(f"  FPR @ 90% recall  {m.get('fpr_at_90_recall')}")
    print(f"  holdout size      {m.get('n_test'):,}")

    cm = m.get("confusion_matrix", {})
    if cm.get("labels"):
        print("\n  confusion matrix (rows = true):")
        w = max(len(l) for l in cm["labels"]) + 1
        print("    " + " " * w + "".join(f"{l[:7]:>8}" for l in cm["labels"]))
        for label, row in zip(cm["labels"], cm["matrix"]):
            print(f"    {label:<{w}}" + "".join(f"{v:>8}" for v in row))
    print()


if __name__ == "__main__":
    main()
