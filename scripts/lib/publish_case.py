"""Publish a self-contained case bundle (case.json + Java source)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


from lib.java_source import resolve_java_source  # noqa: E402


def rewrite_case_paths(case: dict[str, Any], *, rel_file: str) -> dict[str, Any]:
    """Normalize case JSON for a self-contained bundle."""
    out = dict(case)
    out["file"] = rel_file
    out["folder_root"] = "."
    out["scan_root"] = "."
    out["dataset_bundle"] = True
    return out


def publish_real_case(
    *,
    case_path: Path,
    bench_java_root: Path,
    bundle_dir: Path,
    gold_track: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Copy OWASP case JSON + source into bundle_dir/<case_id>/."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case_id = str(case.get("case_id") or case_path.stem.replace("OWASP_benchmark_java_", ""))
    rel_src = str(case.get("file", ""))
    if not rel_src:
        raise ValueError(f"No file path in case {case_path}")

    src_java = resolve_java_source(case, dataset_java_root=bench_java_root)
    if src_java is None:
        raise FileNotFoundError(f"No Java source for {case_id} ({rel_src})")

    bundle_dir = bundle_dir / case_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    dest_rel = rel_src
    dest_java = bundle_dir / dest_rel
    dest_java.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_java, dest_java)

    enriched = rewrite_case_paths(case, rel_file=dest_rel)
    enriched["gold_track"] = gold_track
    if extra:
        enriched.update(extra)

    (bundle_dir / "case.json").write_text(
        json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "case_id": case_id,
        "bundle": str(bundle_dir.relative_to(bundle_dir.parent.parent.parent)),
        "cwe_bucket": extra.get("cwe_bucket") if extra else None,
        "source": dest_rel,
    }


def publish_synthetic_case(
    *,
    bundle_dir: Path,
    case_id: str,
    java_source: str,
    rel_file: str,
    case_json: dict[str, Any],
) -> dict[str, Any]:
    """Write synthetic Java + case.json into bundle."""
    bundle_dir = bundle_dir / case_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    dest_java = bundle_dir / rel_file
    dest_java.parent.mkdir(parents=True, exist_ok=True)
    dest_java.write_text(java_source, encoding="utf-8")

    case = rewrite_case_paths(case_json, rel_file=rel_file)
    case["case_id"] = case_id
    (bundle_dir / "case.json").write_text(
        json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        "case_id": case_id,
        "bundle": case_id,
        "source": rel_file,
    }
