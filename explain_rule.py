from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Union

from avast_py_simulate.rule_explainer import (
    describe_detection_rule,
    format_description_text,
    search_groups_by_name_keyword,
    show_decompiled_rule_raw,
)


def _note_duplicate_numeric_keys(
    stream: Any,
    *,
    n: int,
    rules_sets: List[str],
    key_label: str,
) -> None:
    sl = ", ".join(rules_sets)
    print(
        f"Note: displayed {n} distinct definitions for the same numeric {key_label} "
        f"across rules sets: {sl}. "
        f"These are different malware rules; numeric IDs are scoped per decompiled database. "
        f"Use --engine NAME to restrict to one rules set "
        f"(NAME is the stem before _leaf_signatures.json, e.g. ELFA or DEX).",
        file=stream,
    )


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Look up rules from split JSON (leaf_signatures.json + name_pool.json).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument(
        "-r",
        "--rules-dir",
        type=Path,
        required=True,
        metavar="DIR",
        help="Directory with rules JSON, or path to a specific *leaf_signatures.json file.",
    )
    ap.add_argument(
        "--engine",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Stem of ELFA_leaf_signatures.json / ELFA_name_pool.json (e.g. ELFA, DEX). "
            "Same as scanner.py --engine for JSON rules. Omit to search or show all sets in the folder."
        ),
    )
    ap.add_argument(
        "-f",
        "--find",
        type=str,
        default=None,
        metavar="TEXT",
        help="List groups whose malware name contains this substring (same as --search).",
    )
    ap.add_argument(
        "--search",
        type=str,
        default=None,
        metavar="TEXT",
        help="Same as --find (kept for compatibility).",
    )
    ap.add_argument(
        "--rx",
        "--regex",
        dest="as_regex",
        action="store_true",
        help="Treat --find/--search as regex.",
    )
    ap.add_argument(
        "-S",
        "--case-sensitive",
        "--cs",
        dest="case_sensitive",
        action="store_true",
        help="Case-sensitive --find/--search.",
    )
    ap.add_argument(
        "--show-name-id",
        type=int,
        default=None,
        metavar="N",
        help="Print raw decompiled JSON (one group + leaves). Key = NamePool name_id.",
    )
    ap.add_argument(
        "--show-group-idx",
        type=int,
        default=None,
        metavar="N",
        help="Print raw decompiled JSON. Key = e2p group_idx.",
    )
    ap.add_argument(
        "--yara-name-id",
        type=int,
        default=None,
        metavar="N",
        help="Pseudo-YARA text/JSON. Key = NamePool name_id.",
    )
    ap.add_argument(
        "--yara-group-idx",
        type=int,
        default=None,
        metavar="N",
        help="Pseudo-YARA text/JSON. Key = e2p group_idx.",
    )
    ap.add_argument(
        "-j",
        "--json",
        dest="output_json",
        action="store_true",
        help="With --yara-*: print JSON instead of pseudo-YARA text.",
    )
    ap.add_argument(
        "-a",
        "--anchors-json",
        dest="anchors_json",
        type=Path,
        default=None,
        metavar="FILE",
        help='With --yara-* only: {"leaf_id": anchor} or {"leaf_id": [a1,a2,...]} for multiple hits; resolves at / any([...]).',
    )
    args = ap.parse_args()

    keyword = args.find if args.find is not None else args.search
    if args.find is not None and args.search is not None and args.find != args.search:
        print("Use only one of --find / --search.", file=sys.stderr)
        sys.exit(2)

    has_find = keyword is not None
    has_show = (args.show_name_id is not None) or (args.show_group_idx is not None)
    has_yara = (args.yara_name_id is not None) or (args.yara_group_idx is not None)

    if args.show_name_id is not None and args.show_group_idx is not None:
        print("Use only one of --show-name-id or --show-group-idx.", file=sys.stderr)
        sys.exit(2)
    if args.yara_name_id is not None and args.yara_group_idx is not None:
        print("Use only one of --yara-name-id or --yara-group-idx.", file=sys.stderr)
        sys.exit(2)

    if args.anchors_json is not None and not has_yara:
        print("--anchors-json / -a only applies with --yara-name-id or --yara-group-idx.", file=sys.stderr)
        sys.exit(2)

    modes = sum([has_find, has_show, has_yara])
    if modes != 1:
        print(
            "Use exactly one mode: --find | --show-name-id | --show-group-idx | --yara-name-id | --yara-group-idx",
            file=sys.stderr,
        )
        sys.exit(2)

    rules_loc = Path(args.rules_dir).resolve()
    engine_opt = (args.engine or "").strip() or None

    if has_find:
        rows = search_groups_by_name_keyword(
            rules_dir=rules_loc,
            keyword=keyword,
            case_insensitive=not args.case_sensitive,
            regex=args.as_regex,
            engine=engine_opt,
        )
        if not rows:
            print("(No matching groups.)")
            return
        for r in rows:
            print(
                f"rules_set={r['rules_set']!r}\tgroup_idx={r['group_idx']}\tname_id={r['name_id']}\t"
                f"threshold={r['threshold']}\tleaves={r['leaf_pattern_record_ids']}\t{r['name']!r}"
            )
        sets = sorted({str(r["rules_set"]) for r in rows})
        if len(sets) > 1:
            print(
                f"Note: matches span {len(sets)} rules sets ({', '.join(sets)}). "
                f"Use --engine NAME to limit search to one set.",
                file=sys.stderr,
            )
        return

    if has_show:
        try:
            if args.show_name_id is not None:
                raw: Union[Dict[str, Any], List[Dict[str, Any]]] = show_decompiled_rule_raw(
                    rules_dir=rules_loc, name_id=args.show_name_id, engine=engine_opt
                )
            else:
                raw = show_decompiled_rule_raw(
                    rules_dir=rules_loc, group_idx=args.show_group_idx, engine=engine_opt
                )
        except (LookupError, ValueError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        print(json.dumps(raw, ensure_ascii=False, indent=2))
        if isinstance(raw, list) and len(raw) > 1:
            key_label = "name_id" if args.show_name_id is not None else "group_idx"
            _note_duplicate_numeric_keys(
                sys.stderr,
                n=len(raw),
                rules_sets=[str(x.get("rules_set", "?")) for x in raw],
                key_label=key_label,
            )
        return

    kb10_anchors = None
    if args.anchors_json is not None:
        try:
            raw_anc = json.loads(args.anchors_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"Invalid anchors file: {e}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(raw_anc, dict):
            print("Anchors JSON must be an object.", file=sys.stderr)
            sys.exit(2)
        kb10_anchors = {}
        for k, v in raw_anc.items():
            try:
                kid = int(k)
                if isinstance(v, (list, tuple)):
                    kb10_anchors[kid] = [
                        int(x) if isinstance(x, int) else int(str(x).strip(), 0) for x in v
                    ]
                elif isinstance(v, int):
                    kb10_anchors[kid] = v
                else:
                    kb10_anchors[kid] = int(str(v).strip(), 0)
            except (TypeError, ValueError) as e:
                print(f"Invalid anchor {k!r}:{v!r}: {e}", file=sys.stderr)
                sys.exit(2)

    try:
        if args.yara_name_id is not None:
            desc: Union[Dict[str, Any], List[Dict[str, Any]]] = describe_detection_rule(
                rules_dir=rules_loc,
                name_id=args.yara_name_id,
                kb10_anchors=kb10_anchors,
                engine=engine_opt,
            )
        else:
            desc = describe_detection_rule(
                rules_dir=rules_loc,
                group_idx=args.yara_group_idx,
                kb10_anchors=kb10_anchors,
                engine=engine_opt,
            )
    except (LookupError, ValueError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    if args.output_json:
        print(json.dumps(desc, ensure_ascii=False, indent=2))
    else:
        if isinstance(desc, list):
            for i, d in enumerate(desc):
                if i:
                    sys.stdout.write(f"\n// ----- rules_set={d.get('rules_set')!r} -----\n\n")
                sys.stdout.write(format_description_text(d))
            if len(desc) > 1:
                key_label = "name_id" if args.yara_name_id is not None else "group_idx"
                _note_duplicate_numeric_keys(
                    sys.stderr,
                    n=len(desc),
                    rules_sets=[str(x.get("rules_set", "?")) for x in desc],
                    key_label=key_label,
                )
        else:
            sys.stdout.write(format_description_text(desc))


if __name__ == "__main__":
    main()
