"""Reproducible CWE-stratified case selection (seeded round-robin)."""

from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from .cwe_bucket import cwe_bucket


def select_balanced(paths: list[Path], *, n: int, seed: int) -> list[Path]:
    rng = random.Random(seed)
    by_cat: dict[str, list[Path]] = defaultdict(list)
    for p in paths:
        case = json.loads(p.read_text(encoding="utf-8"))
        by_cat[cwe_bucket(case)].append(p)
    for bucket in by_cat:
        rng.shuffle(by_cat[bucket])

    buckets = sorted(by_cat.keys())
    idx = {b: 0 for b in buckets}
    selected: list[Path] = []
    seen: set[Path] = set()

    while len(selected) < n:
        progressed = False
        for bucket in buckets:
            if len(selected) >= n:
                break
            i = idx[bucket]
            if i < len(by_cat[bucket]):
                p = by_cat[bucket][i]
                idx[bucket] = i + 1
                if p not in seen:
                    selected.append(p)
                    seen.add(p)
                    progressed = True
        if not progressed:
            break

    if len(selected) < n:
        pool: list[Path] = []
        for bucket in buckets:
            pool.extend(by_cat[bucket][idx[bucket] :])
        rng.shuffle(pool)
        for p in pool:
            if len(selected) >= n:
                break
            if p not in seen:
                selected.append(p)
                seen.add(p)

    return selected[:n]


def stratified_split(
    items: list[dict],
    *,
    train_n: int,
    val_n: int,
    test_n: int,
    seed: int,
    bucket_key: str = "cwe_bucket",
) -> dict[str, list[dict]]:
    """Assign items to train/validation/test preserving bucket proportions."""
    assert train_n + val_n + test_n == len(items)
    rng = random.Random(seed)
    by_bucket: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by_bucket[it[bucket_key]].append(it)
    for bucket in by_bucket:
        rng.shuffle(by_bucket[bucket])

    splits: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    targets = {"train": train_n, "validation": val_n, "test": test_n}
    counts = {"train": 0, "validation": 0, "test": 0}
    buckets = sorted(by_bucket.keys())
    idx = {b: 0 for b in buckets}

    while counts["train"] < train_n or counts["validation"] < val_n or counts["test"] < test_n:
        progressed = False
        for bucket in buckets:
            i = idx[bucket]
            if i >= len(by_bucket[bucket]):
                continue
            item = by_bucket[bucket][i]
            idx[bucket] = i + 1
            for split_name in ("train", "validation", "test"):
                if counts[split_name] < targets[split_name]:
                    splits[split_name].append(item)
                    counts[split_name] += 1
                    progressed = True
                    break
        if not progressed:
            break

    # fill any remainder
    remaining = [it for b in buckets for it in by_bucket[b][idx[b] :]]
    rng.shuffle(remaining)
    for it in remaining:
        for split_name in ("train", "validation", "test"):
            if counts[split_name] < targets[split_name]:
                splits[split_name].append(it)
                counts[split_name] += 1
                break

    return splits


def stratified_split_equal_test_per_category(
    items: list[dict],
    *,
    train_n: int,
    val_n: int,
    test_n: int,
    seed: int,
    category_key: str = "borderline_category",
) -> dict[str, list[dict]]:
    """Split so each category contributes equally to test; train/val share the rest."""
    assert train_n + val_n + test_n == len(items)
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by_cat[it[category_key]].append(it)
    n_cats = len(by_cat)
    if test_n % n_cats != 0:
        raise ValueError(f"test_n={test_n} not divisible by {n_cats} categories")
    test_per_cat = test_n // n_cats
    rest_n = train_n + val_n

    rng = random.Random(seed)
    splits: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    for cat in sorted(by_cat.keys()):
        bucket = list(by_cat[cat])
        rng.shuffle(bucket)
        if len(bucket) < test_per_cat:
            raise ValueError(f"category {cat!r} has {len(bucket)} cases, need {test_per_cat} for test")
        splits["test"].extend(bucket[:test_per_cat])
        rest = bucket[test_per_cat:]
        cat_train = round(len(rest) * train_n / rest_n)
        cat_val = len(rest) - cat_train
        splits["train"].extend(rest[:cat_train])
        splits["validation"].extend(rest[cat_train : cat_train + cat_val])

    # Fix off-by-one drift vs global targets (rounding across categories)
    for split_name, target in (("train", train_n), ("validation", val_n)):
        delta = target - len(splits[split_name])
        if delta > 0:
            donor = "validation" if split_name == "train" else "train"
            splits[split_name].extend(splits[donor][-delta:])
            splits[donor] = splits[donor][:-delta]
        elif delta < 0:
            recipient = "validation" if split_name == "train" else "train"
            splits[recipient].extend(splits[split_name][delta:])
            splits[split_name] = splits[split_name][:delta]

    assert len(splits["train"]) == train_n
    assert len(splits["validation"]) == val_n
    assert len(splits["test"]) == test_n
    return splits
