from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union


def promotion_expression_hit(required_leaf_increments: Sequence[Sequence[Any]], threshold: int) -> str:
    """
    YARA-style promotion condition for Avast e2p / single-string.

    hit(id) := 1 if kb10 matched pattern_record_id `id` at least once in the scan window, else 0.
    Detection when sum(weight_i * hit(id_i)) >= threshold (and engine requires counter != 0).
    """
    parts: List[str] = []
    for item in required_leaf_increments:
        if len(item) < 2:
            continue
        lid, w = int(item[0]), int(item[1])
        if w == 1:
            parts.append(f"hit({lid})")
        else:
            parts.append(f"hit({lid})*{w}")
    if not parts:
        inner = "0"
    else:
        inner = " + ".join(parts)
    return f"({inner}) >= {int(threshold)}"


def build_yara_count_promotion_condition(
    required_leaf_increments: Sequence[Sequence[Any]],
    threshold: int,
) -> str:
    """
    Compact pseudo promotion condition using per-leaf presence terms ``leaf_<id>``.
    Each ``leaf_<id>`` is treated as a boolean-like value in ``{0,1}``:
    1 if the leaf matched at least once in the scan pass, else 0.

    Examples:

    - Leaves 812, 813 weight 1 each, threshold 2 -> ``(leaf_812 + leaf_813) >= 2``
    - One leaf repeated many times still contributes 1 for that leaf id.
    """
    entries: List[tuple[int, int]] = []
    for item in required_leaf_increments:
        if len(item) < 2:
            continue
        entries.append((int(item[0]), int(item[1])))
    if not entries:
        return "false"
    th = int(threshold)

    def term(lid: int, w: int) -> str:
        tag = f"leaf_{lid}"
        if w == 1:
            return tag
        return f"({int(w)} * {tag})"

    if len(entries) == 1:
        lid, w = entries[0]
        t = term(lid, w)
        if w == 1 and th <= 1:
            return f"leaf_{lid}"
        if w == 1:
            return f"{t} >= {th}"
        return f"({t}) >= {th}"

    parts = [term(lid, w) for lid, w in entries]
    inner = " + ".join(parts)
    return f"({inner}) >= {th}"


def leaf_expected_positions_to_yara_hex_block(leaf: dict[str, Any]) -> str:
    """
    Build a YARA-style hex string { AA ?? BB ... } from leaf JSON (expected_positions or hex fallback).
    """
    ep: Optional[List[Any]] = leaf.get("expected_positions")
    if isinstance(ep, list) and ep:
        tokens: List[str] = []
        for cell in ep:
            if cell is None:
                tokens.append("??")
            else:
                s = str(cell).strip()
                if s.lower().startswith("0x"):
                    hx = s[2:]
                else:
                    hx = s
                hx = hx.upper()
                if len(hx) == 1:
                    hx = "0" + hx
                elif len(hx) > 2:
                    hx = hx[-2:]
                tokens.append(hx)
        return "{ " + " ".join(tokens) + " }"

    h = leaf.get("compare_bytes_real_hex")
    if isinstance(h, str) and h:
        pairs = [h[i : i + 2].upper() for i in range(0, len(h), 2)]
        return "{ " + " ".join(pairs) + " }"
    return "{ }"


def u8_field_hex(v: Any) -> Optional[str]:
    """Pattern record u8 as 2-digit hex (kb10 shift/length); None if missing."""
    if v is None:
        return None
    try:
        n = int(v) & 0xFF
    except (TypeError, ValueError):
        return None
    return f"0x{n:02X}"


def db_shift_length_at_tuple(shift: Any, length: Any) -> str:
    """
    DB-only tuple (shift_hex, length_hex) from map / leaf_signatures — not a file position.
    Kept for tooling; pseudo-YARA ``at`` prefers ``format_at_pseudo_clause`` when possible.
    """
    sh = u8_field_hex(shift)
    ln = u8_field_hex(length)
    return f"({sh or '?'}, {ln or '?'})"


def leaf_compare_len_u8(leaf: Dict[str, Any]) -> Optional[int]:
    """PatternC ``g()`` / DB u8: how many input bytes are compared — not a file offset and not ``@``."""
    raw = leaf.get("length")
    if raw is None:
        return None
    try:
        return int(raw) & 0xFF
    except (TypeError, ValueError):
        return None


def collect_meta_db_offsets(leaves: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deduplicated shift hex and compare-length (decimal u8) from DB for all leaves (meta block).

    ``unique_lengths_dec`` values are PatternC compare **widths**, not YARA ``@`` offsets.
    """
    shifts: set[str] = set()
    lengths_dec: set[int] = set()
    for leaf in leaves:
        sh = u8_field_hex(leaf.get("shift"))
        if sh is not None:
            shifts.add(sh)
        ln_raw = leaf.get("length")
        try:
            if ln_raw is not None:
                lengths_dec.add(int(ln_raw) & 0xFF)
        except (TypeError, ValueError):
            pass
    return {
        "unique_shifts_hex": sorted(shifts, key=lambda s: int(s, 16)),
        "unique_lengths_dec": sorted(lengths_dec),
    }


def pattern_start_offset_unsigned(anchor: int, shift: Any) -> int:
    """Match kb10: input index = anchor - (shift byte & 0xFF)."""
    try:
        sh = int(shift) & 0xFF
    except (TypeError, ValueError):
        sh = 0
    return int(anchor) - sh


def normalize_kb10_anchors_map(
    kb10_anchors: Optional[Dict[int, Union[int, Sequence[Any]]]],
) -> Dict[int, List[int]]:
    """
    ``leaf_id -> [kb10_anchor, ...]`` — one or many candidate anchors from a scan (multiple hits).
    """
    if not kb10_anchors:
        return {}
    out: Dict[int, List[int]] = {}
    for k, v in kb10_anchors.items():
        lid = int(k)
        if isinstance(v, (list, tuple)):
            parsed: List[int] = []
            for x in v:
                parsed.append(int(x) if isinstance(x, int) else int(str(x).strip(), 0))
            out[lid] = parsed
        else:
            iv = int(v) if isinstance(v, int) else int(str(v).strip(), 0)
            out[lid] = [iv]
    return out


def _hex_off(o: int) -> str:
    return f"0x{int(o) & 0xFFFFFFFFFFFFFFFF:X}"


def format_at_pseudo_clause(
    *,
    leaf_id: int,
    shift: Any,
    kb10_anchor_candidates: Optional[Sequence[int]] = None,
) -> str:
    """
    Pseudo ``at`` for the **first byte** of ``$leaf_<id>`` (YARA ``@leaf_<id>``).

    ``kb10_anchor_candidates``: resolved kb10 anchor(s); multiple values => ``any([start0, start1, ...])``.
    """
    sh_h = u8_field_hex(shift) or "?"
    shift_sym = f"$shift_{int(leaf_id)}"
    lid = int(leaf_id)
    cands = list(kb10_anchor_candidates) if kb10_anchor_candidates is not None else []
    if cands and shift is not None and sh_h != "?":
        starts = [pattern_start_offset_unsigned(a, shift) for a in cands]
        hexes = [_hex_off(s) for s in starts]
        if len(hexes) == 1:
            ah = _hex_off(int(cands[0]))
            return f"{hexes[0]} /* = kb10_anchor - {shift_sym} ({ah} - {sh_h}) */"
        anchors_h = ", ".join(_hex_off(int(a)) for a in cands)
        inner = ", ".join(hexes)
        return f"any([{inner}]) /* @leaf_{lid} start for each kb10_anchor in [{anchors_h}] */"
    if sh_h != "?":
        return f"(kb10_anchor - {shift_sym})"
    return f"(kb10_anchor - {shift_sym} /* shift unknown */)"


def build_yara_pseudo_full_condition(
    leaves: Sequence[Dict[str, Any]],
    threshold: int,
    kb10_anchors: Optional[Dict[int, Union[int, Sequence[Any]]]] = None,
) -> str:
    """
    Pseudo-YARA *condition* (not valid YARA). See ``describe_detection_rule`` ``semantics``.

    Per leaf: ``$leaf at <pattern_start>`` and ``kb10_compare_len``. This is **only** the PatternC slice of kb10; the
    real engine first filters almost all ``n_cur`` via bloom + group record + u32 hash (see ``kb10_scan_matches``).
    ``shift`` maps a **surviving** anchor to ``input_idx = anchor - shift`` for the compare loop — not “shift” in a naive
    substring-search story.
    """
    th = int(threshold)
    anchors_map = normalize_kb10_anchors_map(kb10_anchors)
    items: List[tuple[int, str]] = []
    for leaf in leaves:
        lid = leaf.get("leaf_pattern_record_id")
        if lid is None:
            continue
        lid_i = int(lid)
        w = int(leaf.get("weight", 1))
        cands = anchors_map.get(lid_i, [])
        atp = format_at_pseudo_clause(
            leaf_id=lid_i,
            shift=leaf.get("shift"),
            kb10_anchor_candidates=cands if cands else None,
        )
        clause = f"$leaf_{lid_i} at {atp}"
        clen = leaf_compare_len_u8(leaf)
        if clen is not None:
            clause += f" and kb10_compare_len($leaf_{lid_i}) == {clen}"
        items.append((w, clause))

    if not items:
        return "false"

    if len(items) == 1 and items[0][0] == 1 and th == 1:
        return items[0][1]

    parts: List[str] = []
    for w, clause in items:
        if w == 1:
            parts.append(f"({clause})")
        else:
            parts.append(f"(({clause}) * {w})")
    return f"({' + '.join(parts)}) >= {th}"


def safe_rule_identifier(name: str) -> str:
    """Rough YARA rule name: alphanumeric + underscore."""
    out: List[str] = []
    for ch in name:
        if ch.isalnum():
            out.append(ch)
        elif ch in " ._-":
            out.append("_")
    s = "".join(out).strip("_")
    return s or "unnamed_rule"
