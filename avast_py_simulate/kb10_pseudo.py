"""
Pseudo-YARA text for full kb10 detection path (bloom, group u32 gate, PatternC) + e2p promotion.

Mirrors ``kb10_scan_matches`` / ``PatternC`` in ``avast_py_simulate.engine``. Not valid YARA.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from .yara_like import (
    format_at_pseudo_clause,
    leaf_compare_len_u8,
    normalize_kb10_anchors_map,
)


def _hex_u32(v: int) -> str:
    return f"0x{int(v) & 0xFFFFFFFF:X}"


def _kb10_gate_body(
    *,
    bloom_mask: int,
    group_mask: int,
    scan_limit: int,
) -> str:
    """
    AND-chain (plain newlines; no trailing \\ — YARA allows multiline conditions without line continuations).
    """
    bm = _hex_u32(bloom_mask)
    gm = _hex_u32(group_mask)
    parts: List[str] = [
        "( kb10_n6 := kb10_roll_u32_for_n_cur(kb10_n_cur) )",
        "( kb10_n7 := (((kb10_n6 >>> 17) + kb10_n6) & " + bm + ") )",
        "( ( kb10_u8($kb10_bloom, kb10_n7 >> 3) & (1 << (kb10_n7 & 7)) ) != 0 )",
        "( kb10_grp := (kb10_n7 & " + gm + ") * 16 )",
        "( kb10_t := kb10_n_cur + kb10_s8(kb10_u8($kb10_group_filter, kb10_grp + 3)) )",
        "( ( (kb10_u32le(input, kb10_t) ^ kb10_u32le($kb10_group_filter, kb10_grp + 8)) "
        "& kb10_u32le($kb10_group_filter, kb10_grp + 4) ) == 0 )",
        "( kb10_n_cur_in_engine_window )",
        f"( kb10_scan_limit == {int(scan_limit)} )",
    ]
    return "\n            and ".join(parts)


def _leaf_pattern_conjunct(leaf: Dict[str, Any], anchors_map: Dict[int, List[int]]) -> str:
    lid = leaf.get("leaf_pattern_record_id")
    if lid is None:
        return "false"
    lid_i = int(lid)
    cands = anchors_map.get(lid_i, [])
    atp = format_at_pseudo_clause(
        leaf_id=lid_i,
        shift=leaf.get("shift"),
        kb10_anchor_candidates=cands if cands else None,
    )
    # Quantified variable inside kb10_exists_n_cur is kb10_n_cur (Java n_cur), not kb10_anchor.
    atp = atp.replace("kb10_anchor", "kb10_n_cur")
    parts = [f"( $leaf_{lid_i} at {atp} )"]
    clen = leaf_compare_len_u8(leaf)
    if clen is not None:
        parts.append(f"( kb10_compare_len($leaf_{lid_i}) == {clen} )")
    return " and ".join(parts)


def _exists_one_leaf(
    leaf: Dict[str, Any],
    anchors_map: Dict[int, List[int]],
    gate: str,
) -> str:
    """kb10_exists_n_cur( gate and pattern for $leaf_N )."""
    lp = _leaf_pattern_conjunct(leaf, anchors_map)
    inner = f"{gate}\n            and {lp}"
    return f"kb10_exists_n_cur(\n        {inner}\n    )"


def build_structured_kb10_condition(
    leaves: Sequence[Dict[str, Any]],
    threshold: int,
    kb10: Optional[Dict[str, Any]],
    kb10_anchors: Optional[Dict[int, Union[int, Sequence[Any]]]] = None,
) -> str:
    """
    Full detection as AND/OR pseudo (no C-style spec comments): repeated ``kb10_exists_n_cur`` per leaf
    (each repeats bloom+u32 gate + that leaf's PatternC), summed with weights vs ``threshold``.

    Uses ``kb10_hit`` spelling via ``kb10_exists_n_cur(...)`` tied to ``$leaf_<id>``.
    """
    from .yara_like import build_yara_pseudo_full_condition

    anchors_map = normalize_kb10_anchors_map(kb10_anchors)
    items: List[Dict[str, Any]] = []
    for leaf in leaves:
        if leaf.get("leaf_pattern_record_id") is None:
            continue
        items.append(leaf)

    if not items:
        return "false"

    if not kb10 or not isinstance(kb10, dict):
        return build_yara_pseudo_full_condition(leaves, threshold, kb10_anchors)

    try:
        sl = int(kb10.get("scan_limit", 0))
        bm = int(kb10.get("bloom_mask", 0))
        gm = int(kb10.get("group_mask", 0))
    except (TypeError, ValueError):
        return build_yara_pseudo_full_condition(leaves, threshold, kb10_anchors)

    gate = _kb10_gate_body(
        bloom_mask=bm,
        group_mask=gm,
        scan_limit=sl,
    )

    promo_terms: List[str] = []
    for leaf in items:
        lid_i = int(leaf["leaf_pattern_record_id"])
        w = int(leaf.get("weight", 1))
        ex = _exists_one_leaf(leaf, anchors_map, gate)
        if w == 1:
            promo_terms.append(f"( {ex} )")
        else:
            promo_terms.append(f"( ( {ex} ) * {w} )")

    if len(promo_terms) == 1:
        body = f"{promo_terms[0]} >= {int(threshold)}"
    else:
        joined = "\n        + \n        ".join(promo_terms)
        body = f"(\n        {joined}\n    ) >= {int(threshold)}"

    return body
