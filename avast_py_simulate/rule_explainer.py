from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .kb10_pseudo import build_structured_kb10_condition
from .yara_like import (
    build_yara_count_promotion_condition,
    build_yara_pseudo_full_condition,
    collect_meta_db_offsets,
    leaf_compare_len_u8,
    leaf_expected_positions_to_yara_hex_block,
    normalize_kb10_anchors_map,
    promotion_expression_hit,
    safe_rule_identifier,
)


SUFFIX_LEAF = "_leaf_signatures.json"
SUFFIX_GROUP = "_name_pool.json"


def _valid_prefixed_pairs(rd: Path) -> List[Tuple[Path, Path, str]]:
    """Each ``(leaf, group, prefix)`` where both files exist."""
    out: List[Tuple[Path, Path, str]] = []
    for lf in sorted(rd.glob(f"*{SUFFIX_LEAF}")):
        if not lf.is_file():
            continue
        prefix = lf.name[: -len(SUFFIX_LEAF)]
        gf = rd / f"{prefix}{SUFFIX_GROUP}"
        if gf.is_file():
            out.append((lf, gf, prefix))
    return out


def resolve_rules_dir(rules_dir: Path) -> Path:
    """Directory containing rules; if given a file path, return its parent."""
    p = rules_dir.resolve()
    if p.is_file():
        return p.parent
    return p


def list_rules_json_pairs(
    rules_location: Path,
    engine: Optional[str] = None,
) -> List[Tuple[Path, Path, str]]:
    """
    All ``(leaf_json, group_json, rules_set)`` to use.

    ``rules_set`` is the filename stem (e.g. ``ELFA``).
    This loader accepts only new-format prefixed files:
    ``*_leaf_signatures.json`` + ``*_name_pool.json``.
    """
    loc = rules_location.resolve()
    if loc.is_file():
        parent = loc.parent
        name = loc.name
        if name.endswith(SUFFIX_LEAF):
            prefix = name[: -len(SUFFIX_LEAF)]
            gf = parent / f"{prefix}{SUFFIX_GROUP}"
            if not gf.is_file():
                raise FileNotFoundError(f"Missing paired {gf} for {loc}")
            return [(loc, gf, prefix)]
        raise FileNotFoundError(
            f"Expected *{SUFFIX_LEAF}, got {loc}"
        )

    rd = loc
    en = (engine or "").strip()
    if en:
        lf = rd / f"{en}{SUFFIX_LEAF}"
        gf = rd / f"{en}{SUFFIX_GROUP}"
        if not lf.is_file():
            raise FileNotFoundError(f"Missing {lf}")
        if not gf.is_file():
            raise FileNotFoundError(f"Missing {gf}")
        return [(lf, gf, en)]

    pairs = _valid_prefixed_pairs(rd)
    if pairs:
        return pairs

    loose_leaves = sorted(rd.glob(f"*{SUFFIX_LEAF}"))
    if loose_leaves:
        raise FileNotFoundError(
            f"Incomplete rules in {rd}: found *{SUFFIX_LEAF} but no complete pair with *{SUFFIX_GROUP}: "
            f"{[p.name for p in loose_leaves]}"
        )
    raise FileNotFoundError(
        f"No rules JSON in {rd} (expected *{SUFFIX_LEAF} + *{SUFFIX_GROUP})"
    )


def resolve_rules_json_paths(
    rules_location: Path,
    engine: Optional[str] = None,
) -> Tuple[Path, Path, str]:
    """
    Single leaf + group path. ``ValueError`` if several rule sets exist and ``engine`` is unset.
    """
    pairs = list_rules_json_pairs(rules_location, engine)
    if len(pairs) == 1:
        return pairs[0]
    if len(pairs) > 1:
        stems = ", ".join(p[2] for p in pairs)
        raise ValueError(
            f"Multiple rule sets under {rules_location.resolve()}: {stems}. "
            f"Pass --engine NAME (same stem as ELFA_leaf_signatures.json, e.g. ELFA or DEX)."
        )
    raise FileNotFoundError(f"No rules JSON in {rules_location.resolve()}")


def load_split_rules(
    rules_location: Path,
    engine: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    leaf_path, group_path, _ = resolve_rules_json_paths(rules_location, engine)
    leaf_obj = json.loads(leaf_path.read_text(encoding="utf-8"))
    group_obj = json.loads(group_path.read_text(encoding="utf-8"))
    return leaf_obj, group_obj


def search_groups_by_name_keyword(
    *,
    rules_dir: Path,
    keyword: str,
    case_insensitive: bool = True,
    regex: bool = False,
    engine: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter groups whose malware ``name`` matches ``keyword`` (substring or regex)."""
    if regex:
        flags = re.IGNORECASE if case_insensitive else 0
        pat = re.compile(keyword, flags)

        def match_name(name: str) -> bool:
            return bool(pat.search(name))
    else:
        needle = keyword.lower() if case_insensitive else keyword

        def match_name(name: str) -> bool:
            return needle in (name.lower() if case_insensitive else name)

    rows: List[Dict[str, Any]] = []
    for _lf, gf, rules_set in list_rules_json_pairs(rules_dir, engine):
        try:
            group_obj = json.loads(gf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        label = rules_set
        for g in group_obj.get("groups", []):
            name = g.get("name")
            if not isinstance(name, str):
                continue
            if not match_name(name):
                continue
            inc = g.get("required_leaf_increments") or []
            leaf_ids = sorted({int(x[0]) for x in inc if len(x) >= 1})
            rows.append(
                {
                    "rules_set": label,
                    "group_idx": g.get("group_idx"),
                    "name_id": g.get("name_id"),
                    "name": name,
                    "threshold": g.get("threshold"),
                    "leaf_pattern_record_ids": leaf_ids,
                    "term_count": len(inc),
                }
            )
    return rows


def _find_group(
    groups: List[Dict[str, Any]],
    *,
    name_id: Optional[int] = None,
    group_idx: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    if name_id is None and group_idx is None:
        return None
    for g in groups:
        if name_id is not None and g.get("name_id") == name_id:
            return g
        if group_idx is not None and g.get("group_idx") == group_idx:
            return g
    return None


def _assemble_show_raw_v1(
    leaf_obj: Dict[str, Any],
    group_obj: Dict[str, Any],
    group: Dict[str, Any],
    rules_set: str,
) -> Dict[str, Any]:
    leaf_patterns: Dict[str, Any] = leaf_obj.get("leaf_patterns") or {}
    leaf_entries: List[Dict[str, Any]] = []
    for item in group.get("required_leaf_increments") or []:
        if len(item) < 2:
            continue
        lid, w = int(item[0]), int(item[1])
        key = str(lid)
        raw_leaf = leaf_patterns.get(key)
        leaf_entries.append(
            {
                "leaf_pattern_record_id": lid,
                "weight": w,
                "leaf": copy.deepcopy(raw_leaf) if raw_leaf is not None else None,
            }
        )
    return {
        "schema": "decompiled_rule_view_v1",
        "source": "leaf_signatures.json + name_pool.json (rule_decompiler output)",
        "rules_set": rules_set,
        "engine": leaf_obj.get("engine") or group_obj.get("engine"),
        "engine_type": leaf_obj.get("engine_type") or group_obj.get("engine_type"),
        "group": copy.deepcopy(dict(group)),
        "leaf_entries": leaf_entries,
    }


def show_decompiled_rule_raw(
    *,
    rules_dir: Path,
    name_id: Optional[int] = None,
    group_idx: Optional[int] = None,
    engine: Optional[str] = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Decompiled rule view (no pseudo-YARA). If ``engine`` is unset and several rule sets define
    the same ``name_id`` / ``group_idx``, returns a list of one dict per rules set.
    """
    if (name_id is None) == (group_idx is None):
        raise ValueError("Provide exactly one of name_id or group_idx")

    matches: List[Dict[str, Any]] = []
    for lf, gf, rs in list_rules_json_pairs(rules_dir, engine):
        try:
            leaf_obj = json.loads(lf.read_text(encoding="utf-8"))
            group_obj = json.loads(gf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        group = _find_group(group_obj.get("groups", []), name_id=name_id, group_idx=group_idx)
        if group is None:
            continue
        label = rs
        matches.append(_assemble_show_raw_v1(leaf_obj, group_obj, group, label))

    if not matches:
        raise LookupError(
            f"No group found for name_id={name_id!r} group_idx={group_idx!r}"
        )
    if len(matches) == 1:
        return matches[0]
    return matches


def _compact_promotion_hit_expr(leaves: Sequence[Dict[str, Any]], threshold: int) -> str:
    """Same as name_pool `promotion_expression`, derived from leaves + threshold (no extra storage)."""
    inc: List[List[int]] = []
    for leaf in leaves:
        lid = leaf.get("leaf_pattern_record_id")
        if lid is None:
            continue
        inc.append([int(lid), int(leaf.get("weight", 1))])
    return promotion_expression_hit(inc, int(threshold))


def _kb10_anchor_lists_from_desc_metadata(ka: Any) -> Dict[int, List[int]]:
    """Parse ``kb10_anchors`` from describe JSON (hex string or list of hex strings per leaf)."""
    if not isinstance(ka, dict) or not ka:
        return {}
    out: Dict[int, List[int]] = {}
    for k, v in ka.items():
        try:
            lid = int(k)
        except (TypeError, ValueError):
            continue
        try:
            if isinstance(v, list):
                out[lid] = [
                    int(x) if isinstance(x, int) else int(str(x).strip(), 0) for x in v
                ]
            else:
                out[lid] = [int(v) if isinstance(v, int) else int(str(v).strip(), 0)]
        except (TypeError, ValueError):
            continue
    return out


def _build_describe_detection_dict(
    leaf_obj: Dict[str, Any],
    group_obj: Dict[str, Any],
    group: Dict[str, Any],
    kb10_anchors: Optional[Dict[int, Union[int, Sequence[Any]]]],
    rules_set: str,
) -> Dict[str, Any]:
    leaf_patterns: Dict[str, Any] = leaf_obj.get("leaf_patterns") or {}
    kb10_block = leaf_obj.get("kb10")
    if kb10_block is not None and not isinstance(kb10_block, dict):
        kb10_block = None
    engine = leaf_obj.get("engine") or group_obj.get("engine")
    engine_type = leaf_obj.get("engine_type") or group_obj.get("engine_type")
    malware_name = group.get("name")
    rule_suggestion = safe_rule_identifier(str(malware_name or "malware"))

    terms_in: List[Any] = group.get("required_leaf_increments") or []
    leaves_out: List[Dict[str, Any]] = []
    missing_leaves: List[int] = []

    for item in terms_in:
        if len(item) < 2:
            continue
        lid, w = int(item[0]), int(item[1])
        key = str(lid)
        lp = leaf_patterns.get(key)
        if lp is None:
            missing_leaves.append(lid)
            leaves_out.append(
                {
                    "leaf_pattern_record_id": lid,
                    "weight": w,
                    "yara_hex_string": None,
                    "shift": None,
                    "length": None,
                    "match_type": None,
                    "note": "Not present in leaf_signatures.json (e.g. truncated --max-leaves decompile).",
                }
            )
            continue

        hex_block = leaf_expected_positions_to_yara_hex_block(lp)
        sh = lp.get("shift")
        ln = lp.get("length")
        leaves_out.append(
            {
                "leaf_pattern_record_id": lid,
                "weight": w,
                "yara_hex_string": hex_block,
                "shift": sh,
                "length": ln,
                "match_type": lp.get("match_type"),
                "expected_positions": lp.get("expected_positions"),
                "compare_bytes_real_hex": lp.get("compare_bytes_real_hex"),
                "compare_bytes_db_hex": lp.get("compare_bytes_db_hex"),
                "wildcard_positions": lp.get("wildcard_positions"),
            }
        )

    th_int = int(group.get("threshold") or 0)
    anchors_norm = normalize_kb10_anchors_map(kb10_anchors)
    cond_yara_short = build_yara_count_promotion_condition(terms_in, th_int)
    cond_yara = build_structured_kb10_condition(
        leaves_out,
        th_int,
        kb10_block,
        kb10_anchors if kb10_anchors else None,
    )
    meta_db = collect_meta_db_offsets(leaves_out)

    anchor_meta: Optional[Dict[str, Any]] = None
    if anchors_norm:
        anchor_meta = {}
        for lid, offs in anchors_norm.items():
            if len(offs) == 1:
                anchor_meta[str(lid)] = f"0x{int(offs[0]) & 0xFFFFFFFFFFFFFFFF:X}"
            else:
                anchor_meta[str(lid)] = [
                    f"0x{int(x) & 0xFFFFFFFFFFFFFFFF:X}" for x in offs
                ]

    return {
        "schema": "avast_rule_full_description_v14",
        "rules_set": rules_set,
        "engine": engine,
        "engine_type": engine_type,
        "malware_name": malware_name,
        "name_id": group.get("name_id"),
        "group_idx": group.get("group_idx"),
        "threshold": group.get("threshold"),
        "meta_db_offsets": meta_db,
        "kb10_anchors": anchor_meta,
        "kb10_engine": kb10_block,
        "condition_yara_short": cond_yara_short,
        "condition_yara_pseudo": cond_yara,
        "semantics": (
            "`condition_yara_short`: promotion expression using per-leaf presence terms "
            "`leaf_<pattern_record_id>` (0 or 1) vs `threshold` "
            "(e.g. `(leaf_812 + leaf_813) >= 2`). "
            "A leaf contributes at most 1 even if it appears multiple times in input. "
            "`condition_yara_pseudo`: full kb10 path + promotion (not valid YARA). "
            "`kb10_n6`/`kb10_n7` are decompile guesses. Blobs: `kb10_engine`."
        ),
        "yara_rule_name_suggestion": rule_suggestion,
        "leaves": leaves_out,
        "missing_leaf_pattern_record_ids": missing_leaves,
    }


def describe_detection_rule(
    *,
    rules_dir: Path,
    name_id: Optional[int] = None,
    group_idx: Optional[int] = None,
    kb10_anchors: Optional[Dict[int, Union[int, Sequence[Any]]]] = None,
    engine: Optional[str] = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Full description for one malware group. If ``engine`` is unset and the same numeric
    ``name_id`` / ``group_idx`` exists in several decompiled rule files, returns one dict per rules set.
    """
    if (name_id is None) == (group_idx is None):
        raise ValueError("Provide exactly one of name_id or group_idx")

    matches: List[Dict[str, Any]] = []
    for lf, gf, rs in list_rules_json_pairs(rules_dir, engine):
        try:
            leaf_obj = json.loads(lf.read_text(encoding="utf-8"))
            group_obj = json.loads(gf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        group = _find_group(group_obj.get("groups", []), name_id=name_id, group_idx=group_idx)
        if group is None:
            continue
        label = rs
        matches.append(
            _build_describe_detection_dict(leaf_obj, group_obj, group, kb10_anchors, label)
        )

    if not matches:
        raise LookupError(
            f"No group found for name_id={name_id!r} group_idx={group_idx!r}"
        )
    if len(matches) == 1:
        return matches[0]
    return matches


def format_description_text(desc: Dict[str, Any]) -> str:
    """Compact English, YARA-like layout."""
    name = str(desc.get("malware_name") or "")
    name_esc = name.replace("\\", "\\\\").replace('"', '\\"')
    rule_id = desc.get("yara_rule_name_suggestion") or "malware_rule"
    lines: List[str] = []
    lines.append("// YARA-like rule: strings are hex; condition is pseudo promotion logic.")
    lines.append("// Each leaf_x is boolean-like (0/1): matched at least once => 1, else 0.")
    lines.append(f"rule {rule_id} {{")
    lines.append("  meta:")
    lines.append(f'    malware_name = "{name_esc}"')
    lines.append(f"    name_id = {desc.get('name_id')}")
    lines.append(f"    group_idx = {desc.get('group_idx')}")
    rs = desc.get("rules_set")
    if rs is not None and rs != "":
        lines.append(f"    rules_set = {rs!r}")
    lines.append(f"    engine = {desc.get('engine')!r}")
    lines.append(f"    engine_type = {desc.get('engine_type')!r}")
    mdb = desc.get("meta_db_offsets") or {}
    if mdb.get("unique_shifts_hex"):
        lines.append(f"    db_shifts_hex_unique = {mdb['unique_shifts_hex']}")
    if mdb.get("unique_lengths_dec"):
        lines.append(f"    db_lengths_unique = {mdb['unique_lengths_dec']}")
    kb10_eng = desc.get("kb10_engine")
    if isinstance(kb10_eng, dict) and kb10_eng:
        lines.append('    kb10_ref = "leaf_signatures.json: kb10.*"')
    anch = desc.get("kb10_anchors")
    anc_by_leaf = _kb10_anchor_lists_from_desc_metadata(anch) if anch else {}
    if anch:
        lines.append(f"    kb10_anchor_hex_by_leaf = {anch}")
    lines.append("  strings:")
    for leaf in desc.get("leaves") or []:
        lid = leaf.get("leaf_pattern_record_id")
        if lid is None:
            continue
        hx = leaf.get("yara_hex_string")
        if hx:
            lines.append(f"    $leaf_{lid} = {hx}")
        else:
            lines.append(f"    $leaf_{lid} = {{ }}")
    lines.append("  condition:")
    leaves = desc.get("leaves") or []
    th = int(desc.get("threshold") or 0)
    cond = desc.get("condition_yara_short")
    if not cond:
        inc = [
            [lf["leaf_pattern_record_id"], int(lf.get("weight", 1))]
            for lf in leaves
            if lf.get("leaf_pattern_record_id") is not None
        ]
        cond = build_yara_count_promotion_condition(inc, th)
    if "\n" in cond:
        for cond_line in cond.split("\n"):
            lines.append(f"    {cond_line}")
    else:
        lines.append(f"    {cond}")
    lines.append("}")
    lines.append("")
    miss = desc.get("missing_leaf_pattern_record_ids") or []
    if miss:
        lines.append(f"// WARNING: missing leaf detail for pattern_record_id(s): {miss}")
    return "\n".join(lines)
