from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import engine as adb
from .db_loader import resolve_engine_to_db_paths
from .models import SignatureEntry
from .yara_like import promotion_expression_hit


XOR_KEY = 0xA5


def _safe_rules_output_prefix(label: str) -> str:
    """Sanitize a string for use as ``{prefix}_leaf_signatures.json``."""
    out: List[str] = []
    for ch in label.strip():
        if ch.isalnum() or ch in "_-":
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out).strip("_")
    return s or "rules"


def compute_expected_positions_array(
    pr: Any, *, xor_key: int = XOR_KEY
) -> Tuple[List[Optional[str]], List[int]]:
    """Per-byte PatternC constraints from ``compare_bytes`` / ``wildcard_constant`` (XOR ``xor_key``, default 0xA5)."""
    length = int(pr.length)
    out: List[Optional[str]] = [None] * length
    wildcard_positions: List[int] = []

    wildcard_constant_db = int(pr.wildcard_constant)
    wc_encoded = (wildcard_constant_db ^ xor_key) & 0xFF

    compare_bytes_db: bytes = bytes(pr.compare_bytes)
    for i, stored in enumerate(compare_bytes_db):
        stored_u = stored & 0xFF
        expected_input = (stored_u ^ xor_key) & 0xFF
        if stored_u == wc_encoded and pr.wildcard_constant != 0:
            out[i] = None
            wildcard_positions.append(i)
        else:
            out[i] = f"0x{expected_input:02X}"

    return out, wildcard_positions


def signature_entry_from_pr(pr: Any) -> SignatureEntry:
    expected_positions, wildcard_positions = compute_expected_positions_array(pr)
    compare_bytes_db: bytes = bytes(pr.compare_bytes)
    compare_bytes_real = bytes([(b ^ XOR_KEY) & 0xFF for b in compare_bytes_db])

    match_type = "exact" if int(pr.wildcard_constant) == 0 else "wildcard"

    return SignatureEntry(
        leaf_pattern_record_id=int(pr.pattern_record_id),
        shift=int(pr.shift),
        length=int(pr.length),
        match_type=match_type,
        wildcard_constant_db=int(pr.wildcard_constant),
        compare_bytes_db_hex=compare_bytes_db.hex(),
        compare_bytes_real_hex=compare_bytes_real.hex(),
        expected_positions=expected_positions,
        wildcard_positions=wildcard_positions,
    )


def _list_map_sections(map_bytes: bytes) -> List[Dict[str, int]]:
    """Physical section chain: ``[u32 len][len payload]`` from map offset 16."""
    sections: List[Dict[str, int]] = []
    if len(map_bytes) < 16:
        return sections
    off = 16
    counter = 0
    while off + 4 <= len(map_bytes):
        sec_len = int(adb.u32_le(map_bytes, off))
        payload_start = off + 4
        payload_end = payload_start + sec_len
        if payload_end > len(map_bytes):
            raise ValueError(
                f"Truncated map section counter={counter}: end={payload_end} > file_size={len(map_bytes)}"
            )
        sections.append(
            {
                "counter": counter,
                "length": sec_len,
                "header_offset": off,
                "payload_offset": payload_start,
            }
        )
        off = payload_end
        counter += 1
        if off == len(map_bytes):
            break
    return sections


def _section_lengths_by_counter(sections: List[Dict[str, int]]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for s in sections:
        c = int(s["counter"])
        out[c] = out.get(c, 0) + int(s["length"])
    return out


def _kb10_layout_offsets(map_bytes: bytes) -> Dict[str, Any]:
    """
    Return kb10 layout offsets/sizes for STRINGS_BLOB.
    Offsets are reported both absolute (map file) and relative (within strings_blob payload).
    """
    if len(map_bytes) < 20:
        raise ValueError("map file too small")

    sec0_len_off = 16
    sec0_len = int(adb.u32_le(map_bytes, sec0_len_off))
    sec0_payload_off = sec0_len_off + 4
    sec0_end = sec0_payload_off + sec0_len
    if sec0_end > len(map_bytes):
        raise ValueError("truncated STRINGS_BLOB")

    # kb10 header is 10 u32 words (40 bytes): 9 named + one skipped word.
    if sec0_len < 40:
        raise ValueError("STRINGS_BLOB too small for kb10 header")
    a0 = int(adb.u32_le(map_bytes, sec0_payload_off + 0))
    scan_limit = int(adb.u32_le(map_bytes, sec0_payload_off + 4))
    bloom_len = int(adb.u32_le(map_bytes, sec0_payload_off + 8))
    group_len = int(adb.u32_le(map_bytes, sec0_payload_off + 12))
    pattern_len = int(adb.u32_le(map_bytes, sec0_payload_off + 16))
    var7 = int(adb.u32_le(map_bytes, sec0_payload_off + 20))
    skip2 = int(adb.u32_le(map_bytes, sec0_payload_off + 24))
    skip4 = int(adb.u32_le(map_bytes, sec0_payload_off + 28))
    skip3 = int(adb.u32_le(map_bytes, sec0_payload_off + 32))
    _skip_word = int(adb.u32_le(map_bytes, sec0_payload_off + 36))

    bloom_off_rel = 40
    group_off_rel = bloom_off_rel + bloom_len
    patterns_off_rel = group_off_rel + group_len
    tail_skip_len = skip2 + skip4 + skip3
    tail_off_rel = patterns_off_rel + pattern_len
    if tail_off_rel + tail_skip_len > sec0_len:
        raise ValueError("kb10 layout exceeds STRINGS_BLOB bounds")

    def abs_off(rel_off: int) -> int:
        return sec0_payload_off + rel_off

    return {
        "strings_blob": {
            "section_counter": 0,
            "length": sec0_len,
            "length_offset_abs": sec0_len_off,
            "payload_offset_abs": sec0_payload_off,
            "payload_end_abs": sec0_end,
        },
        "kb10_header": {
            "length": 40,
            "offset_rel": 0,
            "offset_abs": abs_off(0),
            "a0": a0,
            "scan_limit": scan_limit,
            "bloom_len": bloom_len,
            "group_len": group_len,
            "pattern_len": pattern_len,
            "var7": var7,
            "skip2": skip2,
            "skip4": skip4,
            "skip3": skip3,
        },
        "bloom": {
            "offset_rel": bloom_off_rel,
            "offset_abs": abs_off(bloom_off_rel),
            "length": bloom_len,
        },
        "group_filter": {
            "offset_rel": group_off_rel,
            "offset_abs": abs_off(group_off_rel),
            "length": group_len,
            "record_size": 16,
            "record_count": (group_len // 16) if group_len >= 0 else 0,
        },
        "patterns": {
            "offset_rel": patterns_off_rel,
            "offset_abs": abs_off(patterns_off_rel),
            "length": pattern_len,
        },
        "tail_skip": {
            "offset_rel": tail_off_rel,
            "offset_abs": abs_off(tail_off_rel),
            "length": tail_skip_len,
        },
    }


def decompile_assets_to_rules_json(
    *,
    assets_dir: Path,
    engine: str,
    out_dir: Path,
    max_leaves: Optional[int] = None,
    output_filename_prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """Emit leaf + name-pool JSON from ``db_*.nmp`` / ``db_*.map`` and return per-DB summary."""

    nmp_path, map_path, engine_label, db_stem = resolve_engine_to_db_paths(assets_dir, engine)
    nmp_bytes = nmp_path.read_bytes()
    map_bytes = map_path.read_bytes()

    engine_type = adb.detect_datafile_engine(map_bytes)

    kb10_data = adb.parse_kb10_data_from_map(map_bytes, source_label=db_stem)
    patterns_blob = adb.parse_kb10_strings_blob(map_bytes)
    leaf_patterns_list = adb.parse_kb10_pattern_records(patterns_blob)

    np = adb.NamePool(nmp_bytes)
    name_count = int(np.i())

    leaf_patterns_list_sorted = sorted(leaf_patterns_list, key=lambda pr: int(pr.pattern_record_id))
    if max_leaves is not None and max_leaves > 0:
        leaf_patterns_list_sorted = leaf_patterns_list_sorted[:max_leaves]

    leaf_signatures: Dict[str, Any] = {}
    leaf_pattern_ids: List[int] = []

    for pr in leaf_patterns_list_sorted:
        leaf_signatures[str(int(pr.pattern_record_id))] = signature_entry_from_pr(pr).to_json()
        leaf_pattern_ids.append(int(pr.pattern_record_id))

    kb10_block: Dict[str, Any] = {
        "scan_limit": int(kb10_data.scan_limit),
        "layout_offsets": _kb10_layout_offsets(map_bytes),
        "bloom_hex": kb10_data.bloom.hex(),
        "bloom_mask": int(kb10_data.bloom_mask),
        "group_filter_hex": kb10_data.group_filter.hex(),
        "group_mask": int(kb10_data.group_mask),
        "patterns_hex": kb10_data.patterns.hex(),
    }

    groups: List[Dict[str, Any]] = []

    out_dir.mkdir(parents=True, exist_ok=True)
    pfx = _safe_rules_output_prefix(output_filename_prefix or engine_label)
    leaf_out_path = out_dir / f"{pfx}_leaf_signatures.json"
    group_out_path = out_dir / f"{pfx}_name_pool.json"
    file_prefix_meta = pfx

    leaf_out: Dict[str, Any] = {
        "schema_version": 1,
        "engine": engine_label,
        "db_stem": db_stem,
        "rules_json_prefix": file_prefix_meta,
        "engine_type": engine_type,
        "kb10": kb10_block,
        "leaf_patterns": leaf_signatures,
        "generated_leaf_count": len(leaf_pattern_ids),
        "name_pool_count": name_count,
    }
    if max_leaves is not None and max_leaves > 0:
        leaf_out["max_leaves"] = max_leaves

    group_out: Dict[str, Any] = {
        "schema_version": 2,
        "engine": engine_label,
        "db_stem": db_stem,
        "rules_json_prefix": file_prefix_meta,
        "engine_type": engine_type,
        "groups": groups,
        "generated_leaf_count": len(leaf_pattern_ids),
        "name_pool_count": name_count,
    }
    if max_leaves is not None and max_leaves > 0:
        group_out["max_leaves"] = max_leaves

    if engine_type == "SINGLE_STRING":
        for leaf_id in leaf_pattern_ids:
            name_id = leaf_id - 1
            if name_id < 0 or name_id >= name_count:
                continue
            vn = np.d(name_id)
            name = vn.decode_name() if vn is not None else f"UNKNOWN_NAME_ID_{name_id}"

            inc = [[int(leaf_id), 1]]
            groups.append(
                {
                    "group_idx": int(name_id + 1),
                    "name_id": int(name_id),
                    "name": name,
                    "threshold": 1,
                    "required_leaf_increments": inc,
                    "promotion_expression": promotion_expression_hit(inc, 1),
                }
            )
        leaf_out_path.write_text(json.dumps(leaf_out, ensure_ascii=False, indent=2), encoding="utf-8")
        group_out_path.write_text(json.dumps(group_out, ensure_ascii=False, indent=2), encoding="utf-8")
        sections = _list_map_sections(map_bytes)
        return {
            "engine": engine_label,
            "db_stem": db_stem,
            "engine_type": engine_type,
            "name_pool_count": name_count,
            "leaf_count": len(leaf_pattern_ids),
            "group_count": len(groups),
            "section_counters": [s["counter"] for s in sections],
            "section_lengths_by_counter": _section_lengths_by_counter(sections),
            "section_count": len(sections),
        }

    if engine_type != "MULTI_STRING":
        raise SystemExit(f"Unsupported engine_type={engine_type} for {db_stem}")

    e2p_a = adb.parse_e2p_group_mapping(map_bytes, source_label=db_stem)
    d_len = int(e2p_a.b_len())

    required_leaf_increments_by_group: Dict[int, Dict[int, int]] = {i: {} for i in range(1, d_len)}

    for leaf_id in leaf_pattern_ids:
        it = adb.E2pAIter(e2p_a)
        it.c(int(leaf_id))
        while it.a_ready():
            idx = int(it.b_index())
            if 1 <= idx < d_len:
                required_leaf_increments_by_group[idx][leaf_id] = required_leaf_increments_by_group[idx].get(leaf_id, 0) + 1

    for group_idx in range(1, d_len):
        threshold = int(e2p_a.c_threshold(group_idx))
        if threshold == 0:
            continue
        name_id = group_idx - 1
        if name_id < 0 or name_id >= name_count:
            continue
        vn = np.d(name_id)
        name = vn.decode_name() if vn is not None else f"UNKNOWN_NAME_ID_{name_id}"

        req_map = required_leaf_increments_by_group.get(group_idx, {})
        required_leaf_increments = sorted([[int(leaf_id), int(cnt)] for leaf_id, cnt in req_map.items()], key=lambda x: x[0])
        groups.append(
            {
                "group_idx": int(group_idx),
                "name_id": int(name_id),
                "name": name,
                "threshold": threshold,
                "required_leaf_increments": required_leaf_increments,
                "promotion_expression": promotion_expression_hit(required_leaf_increments, threshold),
            }
        )
    leaf_out_path.write_text(json.dumps(leaf_out, ensure_ascii=False, indent=2), encoding="utf-8")
    group_out_path.write_text(json.dumps(group_out, ensure_ascii=False, indent=2), encoding="utf-8")
    sections = _list_map_sections(map_bytes)
    return {
        "engine": engine_label,
        "db_stem": db_stem,
        "engine_type": engine_type,
        "name_pool_count": name_count,
        "leaf_count": len(leaf_pattern_ids),
        "group_count": len(groups),
        "section_counters": [s["counter"] for s in sections],
        "section_lengths_by_counter": _section_lengths_by_counter(sections),
        "section_count": len(sections),
    }

