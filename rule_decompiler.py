from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from avast_py_simulate.db_loader import discover_db_stems
from avast_py_simulate.rule_decompiler import decompile_assets_to_rules_json


def _print_summary(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    total_names = sum(int(r.get("name_pool_count", 0)) for r in rows)
    total_leaf = sum(int(r.get("leaf_count", 0)) for r in rows)
    total_groups = sum(int(r.get("group_count", 0)) for r in rows)
    counter_payload_totals: Dict[int, int] = {}
    counter_labels = {
        0: "STRINGS_BLOB",
        1: "STRING_GROUPS_BLOB",
        2: "RULE_GROUPS_BLOB",
        3: "VIRUS_REPORTS_BLOB",
        4: "HEUR_SUBMITS_BLOB",
        5: "RULE_GROUPS_ID_MAPPER_BLOB",
        6: "NAME_POOL_INDEX_BLOB",
    }
    for r in rows:
        by_counter = r.get("section_lengths_by_counter", {})
        if isinstance(by_counter, dict):
            for c, ln in by_counter.items():
                ci = int(c)
                counter_payload_totals[ci] = counter_payload_totals.get(ci, 0) + int(ln)

    print("\n[summary] decompile results")
    print(f"  databases: {len(rows)}")
    print(f"  total_name_pool_count: {total_names}")
    print(f"  total_leaf_count: {total_leaf}")
    print(f"  total_group_count: {total_groups}")
    if counter_payload_totals:
        print("  section_counter_payload_total_bytes:")
        for c in sorted(counter_payload_totals):
            label = counter_labels.get(c, "UNKNOWN")
            print(f"    [{label}]: {counter_payload_totals[c]}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Decompile Avast db_*.nmp + db_*.map into prefixed JSON pairs per DB "
            "(e.g. ELFA_leaf_signatures.json + ELFA_name_pool.json, DEX_*, …) in one --out-dir. "
            "Pass --engine to decompile a single DB only."
        )
    )
    ap.add_argument(
        "--assets-dir",
        type=Path,
        required=True,
        help="Folder with db_*.nmp and matching db_*.map (mobile assets; .sig not used)",
    )
    ap.add_argument(
        "--engine",
        type=str,
        default=None,
        help=(
            "Optional. If set: decompile only this DB (DEX, ELFA, db_apk, …). "
            "If omitted: decompile every db_*.nmp+.map (each gets its own prefixed filenames in --out-dir)."
        ),
    )
    ap.add_argument(
        "--all-databases",
        action="store_true",
        help="Same as omitting --engine (all db_* pairs). Kept for scripts; no extra effect if --engine is not set.",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Output folder for all JSON (prefixed names per DB; no subdirs by default).",
    )
    ap.add_argument("--max-leaves", type=int, default=0, help="For debugging only. 0=all.")
    args = ap.parse_args()

    max_leaves = None if args.max_leaves in (0, None) else args.max_leaves

    single_engine = (args.engine or "").strip()
    # One explicit DB → flat output under --out-dir
    if single_engine:
        row = decompile_assets_to_rules_json(
            assets_dir=args.assets_dir,
            engine=single_engine,
            out_dir=args.out_dir,
            max_leaves=max_leaves,
        )
        print(f"[+] {single_engine} -> {args.out_dir}")
        _print_summary([row])
        return

    # Default (and --all-databases): every db_*.nmp + .map, same out_dir, distinct filenames
    stems = discover_db_stems(args.assets_dir)
    if not stems:
        raise SystemExit(f"No db_*.nmp with .map found under {args.assets_dir}")
    rows: List[Dict[str, Any]] = []
    for stem in stems:
        row = decompile_assets_to_rules_json(
            assets_dir=args.assets_dir,
            engine=stem,
            out_dir=args.out_dir,
            max_leaves=max_leaves,
        )
        rows.append(row)
        print(f"[+] {stem} -> {args.out_dir}")
    _print_summary(rows)


if __name__ == "__main__":
    main()

