"""Measure a toy classifier on synthetic data and write a fairness summary.

Run this with the Python of a separate environment that has Fairlearn and SHAP. The
toolkit itself does not import either, and `redteam-toolkit fairness-gate` judges the
file this script writes.

Every row is generated here from a seeded random generator. No real person's data is
read. The label depends on two features. A third feature is a proxy that is correlated
with the group. With --bias 0 the label ignores the proxy, so the model has no reason
to use it. With a higher --bias the label leans on the proxy, and a model trained on
the three features then treats the groups differently. The model is a stand-in. It is
not the target of any engagement.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import shap
from fairlearn.metrics import (
    MetricFrame,
    count,
    false_positive_rate,
    selection_rate,
    true_positive_rate,
)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

GROUPS = ("group_a", "group_b")
FEATURES = ("x1", "x2", "proxy")
ROWS = 4000
SHARE_OF_GROUP_B = 0.4
PROXY_SHIFT = 0.8
DIGITS = 6


def make_data(seed: int, bias: float) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    in_b = rng.random(ROWS) < SHARE_OF_GROUP_B
    x1 = rng.normal(size=ROWS)
    x2 = rng.normal(size=ROWS)
    proxy = PROXY_SHIFT * in_b + rng.normal(size=ROWS)
    score = x1 + 0.5 * x2 + bias * proxy + 0.5 * rng.normal(size=ROWS)
    label = (score > np.median(score)).astype(int)
    frame = pd.DataFrame({"x1": x1, "x2": x2, "proxy": proxy})
    group = np.where(in_b, GROUPS[1], GROUPS[0])
    return frame, label, group


def summarize(seed: int, bias: float) -> tuple[dict[str, object], dict[str, float]]:
    frame, label, group = make_data(seed, bias)
    x_train, x_test, y_train, y_test, _, g_test = train_test_split(
        frame, label, group, test_size=0.5, random_state=seed, stratify=label
    )
    model = LogisticRegression(max_iter=1000).fit(x_train, y_train)
    predicted = model.predict(x_test)
    metrics = MetricFrame(
        metrics={
            "count": count,
            "selection_rate": selection_rate,
            "true_positive_rate": true_positive_rate,
            "false_positive_rate": false_positive_rate,
        },
        y_true=y_test,
        y_pred=predicted,
        sensitive_features=g_test,
    )
    groups = [
        {
            "group": str(name),
            "count": int(row["count"]),
            "selection_rate": round(float(row["selection_rate"]), DIGITS),
            "true_positive_rate": round(float(row["true_positive_rate"]), DIGITS),
            "false_positive_rate": round(float(row["false_positive_rate"]), DIGITS),
        }
        for name, row in metrics.by_group.iterrows()
    ]
    # Why: the default masker keeps only 100 background rows. Using all of them makes
    # the values the same on every run and silences SHAP's subsampling notice.
    masker = shap.maskers.Independent(x_train, max_samples=len(x_train))
    explainer = shap.LinearExplainer(model, masker)
    values = np.abs(explainer.shap_values(x_test)).mean(axis=0)
    influence = {
        name: round(float(value), DIGITS)
        for name, value in zip(FEATURES, values, strict=True)
    }
    summary: dict[str, object] = {
        "schema_version": 1,
        "attribute": "group",
        "data": "synthetic",
        "groups": groups,
    }
    return summary, influence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="summary JSON to write")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--bias",
        type=float,
        default=0.0,
        help="how strongly the label leans on the group proxy (default: 0)",
    )
    args = parser.parse_args()
    summary, influence = summarize(args.seed, args.bias)
    Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {args.out} (seed={args.seed} bias={args.bias:g})\n")
    sys.stdout.write("mean absolute SHAP value per feature (not judged by the gate):\n")
    for name, value in sorted(influence.items(), key=lambda item: -item[1]):
        sys.stdout.write(f"  {name}: {value:.4f}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
