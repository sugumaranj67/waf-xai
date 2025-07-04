#!/usr/bin/env python3
"""
scripts/train_attack_classifier.py

Train a reproducible RandomForest on hybrid features (word‐ & char‐TFIDF + side‐stats).
Performs 5×2 repeated stratified CV, logs mean±std for F1 & ROC‐AUC, then
fits on full train set and evaluates on held-out test set.
"""

import os
import argparse
import logging

import numpy as np
import pandas as pd
import joblib

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate
from sklearn.metrics import classification_report, roc_auc_score

from scripts.feature_utils import SideChannelFeatures


def parse_args():
    p = argparse.ArgumentParser("Train WAF-XAI attack classifier")
    p.add_argument(
        "--train-file",
        default="dataset/train/waf_dataset_train.jsonl",
        help="Path to JSONL training set"
    )
    p.add_argument(
        "--test-file",
        default="dataset/test/waf_dataset_test.jsonl",
        help="Path to JSONL test set"
    )
    p.add_argument(
        "--output-model",
        default="models/attack_classifier_pipeline.pkl",
        help="Where to write the trained pipeline"
    )
    p.add_argument(
        "--random-state", type=int, default=42,
        help="Random seed for reproducibility"
    )
    p.add_argument(
        "--n-jobs", type=int, default=-1,
        help="Number of parallel jobs"
    )
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    # 1) Load data
    logging.info("Loading train and test datasets")
    train_df = pd.read_json(args.train_file, lines=True)
    test_df  = pd.read_json(args.test_file,  lines=True)

    X_train, y_train = train_df["input"], train_df["label"]
    X_test,  y_test  = test_df["input"],  test_df["label"]
    logging.info(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # 2) Build pipeline
    pipeline = Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                analyzer="word", ngram_range=(1,2), max_features=5000
            )),
            ("char", TfidfVectorizer(
                analyzer="char", ngram_range=(3,5), max_features=3000
            )),
            ("side", SideChannelFeatures())
        ])),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=args.random_state,
            n_jobs=args.n_jobs
        ))
    ])

    # 3) Repeated stratified CV
    cv = RepeatedStratifiedKFold(
        n_splits=5, n_repeats=2, random_state=args.random_state
    )
    scoring = ["f1_macro", "roc_auc_ovr"]   # fixed scorer name

    logging.info("Running repeated stratified CV (5×2)")
    cv_res = cross_validate(
        pipeline, X_train, y_train,
        cv=cv, scoring=scoring,
        n_jobs=args.n_jobs,
        return_train_score=False
    )

    for metric in scoring:
        scores = cv_res[f"test_{metric}"]
        logging.info(
            f"{metric}: mean={scores.mean():.4f}, std={scores.std():.4f}"
        )

    # 4) Fit on full train set
    logging.info("Fitting pipeline on full training data")
    pipeline.fit(X_train, y_train)

    # 5) Evaluate on hold-out test set
    logging.info("Evaluating on test set")
    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    logging.info("\n" + classification_report(y_test, y_pred, digits=4))

    auc = roc_auc_score(pd.get_dummies(y_test), y_proba, average="macro")
    logging.info(f"Test ROC AUC (macro): {auc:.6f}")

    # 6) Persist artifact
    os.makedirs(os.path.dirname(args.output_model), exist_ok=True)
    joblib.dump(pipeline, args.output_model)
    logging.info(f"Saved trained pipeline to '{args.output_model}'")


if __name__ == "__main__":
    main()