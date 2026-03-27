from __future__ import annotations

from pathlib import Path
from typing import List, Literal, Tuple, Union

EngineName = Literal["DEX", "ELFA"]


def pick_db_map(assets_dir: Path, prefix: str) -> Path:
    """Mobile Avast assets use ``{prefix}.map`` only (``.sig`` is desktop engine, not supported here)."""
    p_map = assets_dir / f"{prefix}.map"
    if p_map.exists():
        return p_map
    raise FileNotFoundError(f"Missing {prefix}.map under {assets_dir}")


def pick_db_files_by_stem(assets_dir: Path, stem: str) -> Tuple[Path, Path]:
    """
    Pair ``{stem}.nmp`` with ``{stem}.map`` (e.g. stem=``db_elfa``).
    """
    nmp = assets_dir / f"{stem}.nmp"
    if not nmp.exists():
        raise FileNotFoundError(f"Missing {nmp}")
    map_path = pick_db_map(assets_dir, stem)
    return nmp, map_path


def pick_db_files(assets_dir: Path, engine: EngineName) -> Tuple[Path, Path]:
    if engine == "DEX":
        return pick_db_files_by_stem(assets_dir, "db_dex")
    return pick_db_files_by_stem(assets_dir, "db_elfa")


def stem_to_engine_label(stem: str) -> str:
    """Short JSON label: db_dex→DEX, db_elfa→ELFA, db_apk→APK."""
    s = stem.lower()
    if s == "db_dex":
        return "DEX"
    if s == "db_elfa":
        return "ELFA"
    if s.startswith("db_") and len(s) > 3:
        return s[3:].upper()
    return stem.upper()


def discover_db_stems(assets_dir: Path) -> List[str]:
    """
    Every ``db_*.nmp`` under ``assets_dir`` that has a sibling ``.map``.
    Sorted by stem name.
    """
    if not assets_dir.is_dir():
        return []
    out: List[str] = []
    for nmp in sorted(assets_dir.glob("db_*.nmp")):
        stem = nmp.stem
        if (assets_dir / f"{stem}.map").exists():
            out.append(stem)
    return out


def resolve_engine_to_db_paths(
    assets_dir: Path, engine: Union[EngineName, str]
) -> Tuple[Path, Path, str, str]:
    """
    Returns ``(nmp_path, map_path, engine_label, db_stem)``.

    - ``DEX`` / ``ELFA`` → fixed stems ``db_dex`` / ``db_elfa``.
    - ``db_foo`` → that stem as-is (must match filenames on disk).
    - ``APK`` / ``foo`` → ``db_apk`` / ``db_foo`` (lowercased suffix).
    """
    raw = str(engine).strip()
    upper = raw.upper()
    if upper == "DEX":
        stem = "db_dex"
    elif upper == "ELFA":
        stem = "db_elfa"
    elif raw.lower().startswith("db_"):
        stem = raw
    else:
        stem = f"db_{raw.lower()}"
    nmp, m = pick_db_files_by_stem(assets_dir, stem)
    return nmp, m, stem_to_engine_label(stem), stem

