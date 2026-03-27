from __future__ import annotations

import argparse
import sys
from pathlib import Path

from avast_py_simulate.simulate import scan_file_with_assets, scan_file_with_rules_json


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-file", type=Path, required=True, help="File to scan (ELF/DEX/ELFA bytes).")
    ap.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help="Avast mobile assets: db_*.nmp + db_*.map (scan from DB).",
    )
    ap.add_argument(
        "--rules-dir",
        type=Path,
        default=None,
        help="Folder with rules JSON, or path to a *leaf_signatures.json file.",
    )
    ap.add_argument(
        "--engine",
        type=str,
        default=None,
        help=(
            "DB scan: DEX, ELFA, or any stem (default ELFA if omitted). "
            "JSON rules scan: same stem as ELFA_leaf_signatures.json when the folder has several rule sets."
        ),
    )
    ap.add_argument("--scan-max-bytes", type=int, default=8_388_608, help="Safety cap for scanning.")
    ap.add_argument(
        "--debug",
        action="store_true",
        help=(
            "stderr: kb10 pipeline stats; each PatternC hit (pattern_record_id, offsets, raw input hex); "
            "final verdict (clean vs name(s)) with e2p / NamePool rationale when applicable."
        ),
    )
    args = ap.parse_args()

    if (args.assets_dir is None and args.rules_dir is None) or (args.assets_dir is not None and args.rules_dir is not None):
        raise SystemExit("Provide exactly one of --assets-dir (DB scan) or --rules-dir (JSON scan).")

    if args.rules_dir is not None:
        rules_loc = args.rules_dir.resolve()
        rengine = (args.engine or "").strip() or None
        try:
            hits = scan_file_with_rules_json(
                rules_dir=rules_loc,
                engine=rengine,
                input_file=args.scan_file,
                scan_max_bytes=args.scan_max_bytes,
                debug=args.debug,
                debug_stream=sys.stderr,
            )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            raise SystemExit(1) from None
    else:
        hits = scan_file_with_assets(
            assets_dir=args.assets_dir,
            input_file=args.scan_file,
            engine=args.engine or "ELFA",
            scan_max_bytes=args.scan_max_bytes,
            debug=args.debug,
            debug_stream=sys.stderr,
        )

    for name in hits[:100]:
        print(name)


if __name__ == "__main__":
    main()

