from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple, Union

from . import engine as avast_engine
from .db_loader import EngineName, resolve_engine_to_db_paths
from .rule_explainer import resolve_rules_json_paths


def print_kb10_scan_debug(
    *,
    title: str,
    input_file: Path,
    file_len: int,
    scan_max_bytes: Optional[int],
    stats: Dict[str, Any],
    hit_records: Optional[List[Dict[str, Any]]] = None,
    stream: TextIO = sys.stderr,
) -> None:
    """Print kb10 stats / optional hit dumps (for ``--debug``)."""
    cap = scan_max_bytes if scan_max_bytes is not None else file_len
    eff = min(file_len, cap)
    print(f"[debug] {title}", file=stream)
    print(f"  input_file: {input_file}", file=stream)
    print(f"  file_size_bytes: {file_len}  scan_cap: {cap}  effective_scan_len: {eff}", file=stream)
    if stats.get("scan_early_exit_short_input"):
        print("  early_exit: input shorter than 4 bytes (kb10 not run)", file=stream)
        return
    print(
        f"  kb10: scan_buffer_len={stats.get('scan_buffer_len')}  "
        f"scan_limit_from_map={stats.get('scan_limit_from_map')}  "
        f"n2={stats.get('n2')}  n3_phase1_last_n_cur={stats.get('n3_phase1_last_n_cur')}",
        file=stream,
    )
    print(
        f"  kb10: bloom_len={stats.get('bloom_len_bytes')} B  "
        f"group_filter_len={stats.get('group_filter_len_bytes')} B",
        file=stream,
    )
    p1 = stats.get("phase1_n_cur_positions", 0)
    p2 = stats.get("phase2_n_cur_positions", 0)
    p3 = stats.get("phase3_n_cur_positions", 0)
    print(
        f"  phases: phase1_positions={p1}  phase2_positions={p2}  phase3_positions={p3}  "
        f"total_n_cur={p1 + p2 + p3}",
        file=stream,
    )
    print(
        f"  bloom: pass={stats.get('bloom_filter_pass', 0)}  miss={stats.get('bloom_filter_miss', 0)}  "
        f"bad_index={stats.get('bloom_bad_index', 0)}",
        file=stream,
    )
    print(
        f"  u32_gate: pass={stats.get('u32_group_gate_pass', 0)}  miss={stats.get('u32_group_gate_miss', 0)}  "
        f"read_bounds_fail={stats.get('u32_read_bounds_fail', 0)}",
        file=stream,
    )
    print(
        f"  PatternC: compare_try={stats.get('pattern_compare_try', 0)}  "
        f"compare_hit={stats.get('pattern_compare_hit', 0)}",
        file=stream,
    )
    print(
        f"  results: raw_match_tuples={stats.get('raw_match_tuples', 0)}  "
        f"unique_pattern_record_ids={stats.get('unique_pattern_record_ids', 0)}",
        file=stream,
    )
    if stats.get("hit_records_capped"):
        print(
            f"  note: pattern hit hex dump capped at hit_record_limit "
            f"(stored={stats.get('hit_records_stored', '?')})",
            file=stream,
        )
    if hit_records:
        print("  PatternC hits (raw file bytes at input_start_offset; XOR 0xA5 applied in engine, not in hex):", file=stream)
        for i, rec in enumerate(hit_records):
            pid = rec.get("pattern_record_id")
            anc = rec.get("kb10_anchor")
            off = rec.get("input_start_offset")
            ln = rec.get("compare_len")
            mode = rec.get("match_mode", "?")
            hx = rec.get("input_bytes_hex", "")
            note = rec.get("note")
            extra = f"  [{note}]" if note else ""
            print(
                f"    #{i + 1}  pattern_record_id={pid}  kb10_anchor={anc}  "
                f"input_start_offset={off}  compare_len={ln}  mode={mode}{extra}",
                file=stream,
            )
            if hx:
                print(f"         hex: {hx}", file=stream)


def print_assets_final_verdict_debug(
    *,
    stream: TextIO,
    engine_type: str,
    map_name: str,
    leaf_pattern_ids: List[int],
    selected_name_ids: List[int],
    detected_names: List[str],
    np_decode_fail_ids: List[int],
    e2p_rows: Optional[List[Tuple[int, int, int]]] = None,
) -> None:
    """DB-asset scan: kb10 + promotion + NamePool outcome."""
    print("[debug] ========== final verdict (this engine / map) ==========", file=stream)
    print(f"  map_engine_type: {engine_type!r}  ({map_name})", file=stream)
    if not leaf_pattern_ids:
        print(
            "  kb10: no PatternC string match in scan window → no leaf pattern_record_id fired.",
            file=stream,
        )
        print(
            "  conclusion: clean at this engine’s string layer (no malware names emitted from this map).",
            file=stream,
        )
        return

    print(
        f"  kb10: leaf pattern_record_id hit(s) (unique): {leaf_pattern_ids}",
        file=stream,
    )

    if engine_type == "SINGLE_STRING":
        print(
            "  promotion (lhz): NamePool id = pattern_record_id - 1 for each hit (Java port).",
            file=stream,
        )
        if detected_names:
            print(f"  detected malware name(s): {detected_names}", file=stream)
            print("  conclusion: signature name(s) resolved from NamePool.", file=stream)
        else:
            print(
                f"  NamePool decode failed for id(s): {np_decode_fail_ids} "
                f"(expected ids from pattern_record_id-1: {selected_name_ids}).",
                file=stream,
            )
            print(
                "  conclusion: kb10 matched but no displayable name (missing NamePool entry).",
                file=stream,
            )
        return

    print(
        "  promotion (e2p): counters per map slot idx fed by E2pAIter from leaf hits; "
        "emit NamePool id (idx-1) when counter != 0 and counter >= threshold(idx) and threshold != 0.",
        file=stream,
    )
    if e2p_rows is not None and e2p_rows:
        print("  e2p slots with non-zero counter after scan:", file=stream)
        for idx, cnt, thr in e2p_rows:
            would = thr != 0 and cnt >= thr
            name_pool_id = idx - 1
            print(
                f"    slot_idx={idx}  counter={cnt}  threshold={thr}  "
                f"would_promote={would}  name_pool_id_if_promoted={name_pool_id}",
                file=stream,
            )
    elif e2p_rows is not None:
        print(
            "  e2p: no slot received a non-zero counter from these leaf hits "
            "(leaf ids do not map into e2p increment stream for this map).",
            file=stream,
        )

    if detected_names:
        print(f"  detected malware name(s): {detected_names}", file=stream)
        print("  conclusion: at least one e2p slot reached threshold → name(s) from NamePool.", file=stream)
    else:
        print(
            "  detected malware name(s): (none) — no e2p slot satisfied threshold, or NamePool decode failed.",
            file=stream,
        )
        print(
            "  conclusion: kb10 matched substring(s) but MULTI_STRING rule set did not promote to a final name.",
            file=stream,
        )


def print_json_final_verdict_debug(
    *,
    stream: TextIO,
    leaf_hits: List[int],
    detected_names: List[str],
    groups_detail: List[Dict[str, Any]],
) -> None:
    """JSON rules scan: group thresholds vs leaf hits."""
    print("[debug] ========== final verdict (JSON name_pool) ==========", file=stream)
    lids = sorted(leaf_hits)
    if not lids:
        print("  kb10: no PatternC match → no leaf ids in hit set.", file=stream)
        print("  conclusion: clean for this rules folder.", file=stream)
        return

    print(f"  kb10: leaf id hit(s): {lids}", file=stream)
    if detected_names:
        print(f"  detected name(s): {detected_names}", file=stream)
        print(
            "  conclusion: at least one group had counter != 0 and counter >= threshold (e2p-style JSON port).",
            file=stream,
        )
        return

    print(
        "  promotion: no group reached threshold with a non-zero counter "
        "(same idea as Java e2p: need weighted leaf contributions).",
        file=stream,
    )
    if groups_detail:
        print("  per-group (threshold > 0):", file=stream)
        for row in groups_detail:
            print(
                f"    name={row.get('name')!r}  threshold={row.get('threshold')}  "
                f"counter_after_scan={row.get('counter')}  "
                f"contributing_leafs={row.get('contributing')!r}",
                file=stream,
            )
    print("  conclusion: kb10 hit(s) present but no malware name triggered.", file=stream)


_E2P_COUNTER_SAT = 32767  # matches ``e2p_promote`` saturation


def scan_file_with_assets(
    *,
    assets_dir: Path,
    input_file: Path,
    engine: Union[EngineName, str] = "ELFA",
    scan_max_bytes: Optional[int] = 8_388_608,
    debug: bool = False,
    debug_stream: TextIO = sys.stderr,
) -> List[str]:
    """Scan file with kb10 + promotion using ``db_*.nmp`` / ``db_*.map``."""

    nmp_path, map_path, engine_label, db_stem = resolve_engine_to_db_paths(assets_dir, engine)
    nmp_bytes = nmp_path.read_bytes()
    map_bytes = map_path.read_bytes()

    engine_type = avast_engine.detect_datafile_engine(map_bytes)

    kb10_data = avast_engine.parse_kb10_data_from_map(map_bytes, source_label=db_stem)
    input_bytes = input_file.read_bytes()
    file_len = len(input_bytes)
    kb10_stats: Optional[Dict[str, Any]] = {} if debug else None
    hit_records: Optional[List[Dict[str, Any]]] = [] if debug else None
    matches = avast_engine.kb10_scan_matches(
        data=kb10_data,
        input_bytes=input_bytes,
        max_bytes=scan_max_bytes,
        target_pattern_id=None,
        out_stats=kb10_stats,
        out_hit_records=hit_records,
    )
    leaf_pattern_ids = sorted({pid for pid, _anchor in matches})

    if debug and kb10_stats is not None:
        print_kb10_scan_debug(
            title=f"kb10 scan ({engine_label} / {db_stem} / {map_path.name})",
            input_file=input_file,
            file_len=file_len,
            scan_max_bytes=scan_max_bytes,
            stats=kb10_stats,
            hit_records=hit_records,
            stream=debug_stream,
        )

    np = avast_engine.NamePool(nmp_bytes)

    e2p_a = None
    if engine_type == "MULTI_STRING":
        e2p_a = avast_engine.parse_e2p_group_mapping(map_bytes, source_label=db_stem)
        selected_name_ids = avast_engine.e2p_promote(leaf_pattern_ids, e2p_a)
    elif engine_type == "SINGLE_STRING":
        selected_name_ids = [(pid - 1) for pid in leaf_pattern_ids if pid >= 1]
    else:
        raise ValueError(f"Unknown map engine_type={engine_type} for {map_path}")

    if debug:
        print(
            f"[debug] promotion: engine_type={engine_type!r}  "
            f"leaf_pattern_ids_count={len(leaf_pattern_ids)}  "
            f"promoted_name_pool_ids={len(selected_name_ids)}",
            file=debug_stream,
        )

    out: List[str] = []
    seen: set[str] = set()
    np_decode_fail_ids: List[int] = []
    for name_id in selected_name_ids:
        vn = np.d(int(name_id))
        if vn is None:
            np_decode_fail_ids.append(int(name_id))
            continue
        name = vn.decode_name()
        if name in seen:
            continue
        seen.add(name)
        out.append(name)

    if debug:
        e2p_rows = None
        if engine_type == "MULTI_STRING" and e2p_a is not None and leaf_pattern_ids:
            e2p_rows = avast_engine.e2p_counters_after_leaf_scan(leaf_pattern_ids, e2p_a)
        print_assets_final_verdict_debug(
            stream=debug_stream,
            engine_type=engine_type,
            map_name=map_path.name,
            leaf_pattern_ids=leaf_pattern_ids,
            selected_name_ids=selected_name_ids,
            detected_names=out,
            np_decode_fail_ids=np_decode_fail_ids,
            e2p_rows=e2p_rows,
        )

    return out


def scan_file_with_rules_json(
    *,
    rules_dir: Path,
    input_file: Path,
    scan_max_bytes: Optional[int] = 8_388_608,
    debug: bool = False,
    debug_stream: TextIO = sys.stderr,
    engine: Optional[str] = None,
) -> List[str]:
    """Scan using decompiled leaf + group JSON (see ``resolve_rules_json_paths``)."""

    leaf_path, group_path, _pfx = resolve_rules_json_paths(rules_dir, engine)

    leaf_obj = json.loads(leaf_path.read_text(encoding="utf-8"))
    group_obj = json.loads(group_path.read_text(encoding="utf-8"))

    kb10 = leaf_obj["kb10"]
    kb10_data = avast_engine.KB10Data(
        scan_limit=int(kb10["scan_limit"]),
        bloom=bytes.fromhex(kb10["bloom_hex"]),
        bloom_mask=int(kb10["bloom_mask"]),
        group_filter=bytes.fromhex(kb10["group_filter_hex"]),
        group_mask=int(kb10["group_mask"]),
        patterns=bytes.fromhex(kb10["patterns_hex"]),
    )

    input_bytes = input_file.read_bytes()
    file_len = len(input_bytes)
    kb10_stats: Optional[Dict[str, Any]] = {} if debug else None
    hit_records: Optional[List[Dict[str, Any]]] = [] if debug else None
    matches = avast_engine.kb10_scan_matches(
        data=kb10_data,
        input_bytes=input_bytes,
        max_bytes=scan_max_bytes,
        target_pattern_id=None,
        out_stats=kb10_stats,
        out_hit_records=hit_records,
    )
    leaf_hits = {int(pid) for pid, _anchor in matches}

    if debug and kb10_stats is not None:
        print_kb10_scan_debug(
            title=f"kb10 scan (JSON rules / {leaf_path.name})",
            input_file=input_file,
            file_len=file_len,
            scan_max_bytes=scan_max_bytes,
            stats=kb10_stats,
            hit_records=hit_records,
            stream=debug_stream,
        )

    out: List[str] = []
    seen: set[str] = set()
    groups_checked = 0
    groups_fired = 0
    groups_detail: List[Dict[str, Any]] = []
    for group in group_obj.get("groups", []):
        threshold = int(group["threshold"])
        if threshold == 0:
            continue
        groups_checked += 1
        counter = 0
        contributing: List[int] = []
        for leaf_id, weight in group.get("required_leaf_increments", []):
            lid = int(leaf_id)
            if lid in leaf_hits:
                contributing.extend([lid] * int(weight))
                for _ in range(int(weight)):
                    if counter < _E2P_COUNTER_SAT:
                        counter += 1

        if counter != 0 and counter >= threshold:
            groups_fired += 1
            name = group.get("name")
            if isinstance(name, str) and name and name not in seen:
                seen.add(name)
                out.append(name)
        elif debug:
            req_ids = {int(x[0]) for x in group.get("required_leaf_increments", [])}
            if counter > 0 or (leaf_hits and req_ids & leaf_hits):
                groups_detail.append(
                    {
                        "name": group.get("name"),
                        "threshold": threshold,
                        "counter": counter,
                        "contributing": sorted(set(contributing)),
                    }
                )

    if debug:
        print(
            f"[debug] JSON promotion: leaf_hits_count={len(leaf_hits)}  "
            f"groups_threshold_gt0_checked={groups_checked}  groups_triggered={groups_fired}  "
            f"unique_output_names={len(out)}",
            file=debug_stream,
        )
        print_json_final_verdict_debug(
            stream=debug_stream,
            leaf_hits=sorted(leaf_hits),
            detected_names=out,
            groups_detail=groups_detail,
        )

    return out

