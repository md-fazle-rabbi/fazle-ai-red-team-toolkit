"""Measure a toy classifier under small numeric perturbations and write a summary.

Run this with the Python of a separate environment that has IBM ART and scikit-learn.
The toolkit itself does not import either, and `redteam-toolkit robustness-gate`
judges the file this script writes.

Every row is generated here from a seeded random generator. No real person's data is
read. The only attack is the Fast Gradient Method from ART, which nudges each number
in a row by at most epsilon in the direction that raises the model's loss. There are
no prompts, no text and no network calls. The model is a stand-in. It is not the
target of any engagement.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np

with warnings.catch_warnings():
    # Why: ART warns at import when PyTorch is absent. This script does not use it.
    warnings.simplefilter("ignore", UserWarning)
    from art.attacks.evasion import FastGradientMethod
    from art.estimators.classification import SklearnClassifier

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

FEATURES = 6
ROWS = 4000
EPSILONS = (0.05, 0.1, 0.3)
DIGITS = 6


def make_data(seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = rng.normal(size=(ROWS, FEATURES))
    weights = np.linspace(1.0, 0.3, FEATURES)
    score = x @ weights + 0.5 * rng.normal(size=ROWS)
    label = (score > np.median(score)).astype(int)
    return x, label


def accuracy(model: LogisticRegression, x: np.ndarray, y: np.ndarray) -> float:
    return round(float((model.predict(x) == y).mean()), DIGITS)


def summarize(
    seed: int, epsilons: tuple[float, ...]
) -> tuple[dict[str, object], float, list[tuple[float, float]]]:
    x, y = make_data(seed)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.5, random_state=seed, stratify=y
    )
    model = LogisticRegression(max_iter=1000).fit(x_train, y_train)
    classifier = SklearnClassifier(model=model)
    clean = accuracy(model, x_test, y_test)
    measured: list[tuple[float, float]] = []
    for epsilon in epsilons:
        attack = FastGradientMethod(classifier, eps=epsilon)
        perturbed = attack.generate(x=x_test)
        measured.append((epsilon, accuracy(model, perturbed, y_test)))
    summary: dict[str, object] = {
        "schema_version": 1,
        "data": "synthetic",
        "model": "logistic_regression",
        "attack": "fast_gradient_method",
        "rows": len(x_test),
        "clean_accuracy": clean,
        "points": [{"epsilon": e, "accuracy": a} for e, a in measured],
    }
    return summary, clean, measured


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="summary JSON to write")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--epsilon",
        type=float,
        action="append",
        help="perturbation size to measure, repeatable (default: 0.05 0.1 0.3)",
    )
    args = parser.parse_args()
    epsilons = tuple(sorted(set(args.epsilon))) if args.epsilon else EPSILONS
    summary, clean, measured = summarize(args.seed, epsilons)
    Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {args.out} (seed={args.seed})\n")
    sys.stdout.write(f"clean accuracy: {clean:.4f}\n")
    for epsilon, value in measured:
        sys.stdout.write(f"  epsilon {epsilon:g}: {value:.4f}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
