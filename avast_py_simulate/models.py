from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SignatureEntry:
    leaf_pattern_record_id: int
    shift: int
    length: int
    match_type: str  # exact|wildcard
    wildcard_constant_db: int
    compare_bytes_db_hex: str
    compare_bytes_real_hex: str
    # Same semantics as PatternC compare loop (decode of compare_bytes ^ 0xA5); null => wildcard slot
    expected_positions: List[Optional[str]]
    wildcard_positions: List[int]

    def to_json(self) -> Dict[str, Any]:
        return {
            "leaf_pattern_record_id": self.leaf_pattern_record_id,
            "shift": self.shift,
            "length": self.length,
            "match_type": self.match_type,
            "wildcard_constant_db": self.wildcard_constant_db,
            "compare_bytes_db_hex": self.compare_bytes_db_hex,
            "compare_bytes_real_hex": self.compare_bytes_real_hex,
            "expected_positions": self.expected_positions,
            "wildcard_positions": self.wildcard_positions,
        }

