#!/usr/bin/env python3
"""
feature_utils.py

Defines a transformer extracting side-channel stats from text:
  - length of input
  - special/non-alphanumeric char count
  - ratio of special chars
  - Shannon entropy of character distribution
"""

import numpy as np
from collections import Counter
from sklearn.base import BaseEstimator, TransformerMixin


class SideChannelFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        feats = []
        for text in X:
            length = len(text)
            special = sum(1 for c in text if not c.isalnum() and not c.isspace())
            ratio = special / length if length else 0.0

            counts = np.array(list(Counter(text).values()), dtype=float)
            probs = counts / counts.sum() if counts.sum() else np.array([0.0])
            entropy = -np.sum(probs * np.log2(probs + 1e-9))

            feats.append([length, special, ratio, entropy])
        return np.array(feats)
