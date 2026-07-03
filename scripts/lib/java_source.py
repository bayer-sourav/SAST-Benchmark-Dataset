"""Resolve Java source paths for OWASP benchmark cases."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def resolve_java_source(case: dict[str, Any], *, dataset_java_root: Path) -> Path | None:
    """Find Java source for a corpus case.

    Tries bundle_root from phase2 corpora, per-case fp/tp bundles in the dataset,
    then the monolithic OWASP BenchmarkJava checkout (sibling of Projects/).
    """
    rel = case.get("file")
    if not rel:
        return None

    candidates: list[Path] = []
    bundle_root = case.get("bundle_root") or case.get("repo_root")
    if bundle_root:
        candidates.append(Path(str(bundle_root)) / rel)

    case_id = case.get("case_id")
    if case_id:
        for track in ("fp", "tp"):
            for split in ("train", "validation", "test"):
                candidates.append(dataset_java_root / track / split / str(case_id) / rel)

    candidates.append(dataset_java_root / rel)

    mono = dataset_java_root.parent.parent / "BenchmarkJava"
    if mono.is_dir():
        candidates.append(mono / rel)

    for path in candidates:
        if path.is_file():
            return path
    return None
