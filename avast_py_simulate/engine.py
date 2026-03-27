"""Avast mobile DB port: NamePool (``db_*.nmp``), kb10 / e2p (``db_*.map``). Used by ``avast_py_simulate``."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Byte helpers (Java-like)
# ----------------------------


def u32_le(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"u32_le out of bounds: off={off} len={len(buf)}")
    return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)


def is_power_of_two(x: int) -> bool:
    return x != 0 and ((x - 1) & x) == 0


class ByteCursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def require(self, n: int, ctx: str) -> None:
        if self.pos + n > len(self.data):
            raise ValueError(f"Truncated while parsing {ctx}: need {n}, remaining={self.remaining()}")

    def read_u32(self, ctx: str) -> int:
        self.require(4, ctx)
        v = u32_le(self.data, self.pos)
        self.pos += 4
        return v

    def read_bytes(self, n: int, ctx: str) -> bytes:
        self.require(n, ctx)
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def skip(self, n: int, ctx: str) -> None:
        self.require(n, ctx)
        self.pos += n


# ----------------------------
# NamePool (db_*.nmp) decoder
# ----------------------------


@dataclass(frozen=True)
class NamePoolVirusName:
    name_bytes: bytes
    flags: int

    def decode_name(self) -> str:
        # Decompilation uses platform default charset for some places; in practice these names are UTF-8-like.
        return self.name_bytes.decode("utf-8", errors="replace").rstrip("\x00")


class NamePool:
    def __init__(self, raw: bytes):
        if raw is not None and len(raw) != 0:
            b0 = raw[0]
            if (b0 & 0x80) != 0 or (b0 & 0xFF) < 32:
                self.a = bytearray(raw)
            else:
                self.a = bytearray()
        else:
            self.a = bytearray()

        self.b: Optional[List[int]] = None  # index table
        self.c: int = -1  # cached count

    def _a_count(self) -> int:
        # Port of NamePool.a()
        var5 = self.a
        var3 = 0
        var1 = 0
        if var5 is not None:
            var2 = len(var5)
            while True:
                var3 = var1
                if var2 <= 0:
                    break
                while True:
                    var3 = var2 - 1
                    var4 = var5[var3]
                    if (var4 & 0xFF) >= 128 or (var4 & 0xE0) == 0:
                        var2 = var3
                        if (var4 & 0xF0) == 16:
                            var2 = var3 - 1
                        var1 += 1
                        break
                    var2 = var3
        return var3

    def i(self) -> int:
        if self.c == -1:
            self.c = self._a_count()
        return self.c

    def l(self, x: int) -> int:
        # NamePool.l(byte var1) => (byte)(var1 ^ 21)
        return (x ^ 21) & 0xFF

    def k(self, dst: bytearray, dst_off: int, src: bytes, src_off: int, length: int) -> int:
        # NamePool.k(byte[] dst,int dstOff, byte[] src,int srcOff,int len)
        var6 = length
        # Decompiled code limits writes by destination buffer remaining space.
        if length > len(dst) - dst_off:
            var6 = len(dst) - dst_off
        if var6 < 0:
            return 0
        # Additional safety: keep reads in-bounds (Java code assumes the inputs are valid).
        if src_off + var6 > len(src):
            var6 = len(src) - src_off
        var7 = dst_off
        var_written = var6
        while var_written != 0:
            dst[var7] = self.l(src[src_off])
            src_off += 1
            var7 += 1
            var_written -= 1
        return var6

    def c_decode(self, out: bytearray, out_off: int, length: int) -> int:
        # Port of NamePool.c(byte[] var1, int var2, int var3)
        var5 = length
        while True:
            var6_raw = self.a[var5]  # 0..255
            # Java `byte` -> sign-extended int
            var6 = var6_raw - 256 if var6_raw >= 128 else var6_raw

            if (var6 & 0xFF) >= 128 or (var6 & 0xE0) == 0:
                var4 = out_off
                if var6 != 0:
                    if (var6 & 0xFF) < 16:
                        var4 = 0
                        var6_pos = var5
                        while True:
                            var7_raw = self.a[var6_pos]
                            var7 = var7_raw - 256 if var7_raw >= 128 else var7_raw
                            if (var7 & 0xFF) >= 16:
                                out_off = self.c_decode(out, out_off, var6_pos)
                                var6_pos = out_off - 1
                                out[var6_pos] = (out[var6_pos] + var4) & 0xFF
                                var4 = out_off
                                break
                            var6_pos -= 1
                            var4 += var7
                    elif (var6 & 0xFF) < 128:
                        var4 = self.c_decode(
                            out,
                            out_off,
                            ((var6 & 15) << 7) - 2049 + (self.a[var5 - 1] & 0x7F) + var5,
                        )
                    else:
                        var4 = self.c_decode(out, out_off, var6 + var5)  # var6 is signed (Java behavior)

                out_off = var4
                if length != var5:
                    length -= var5
                    out_off = length
                    if length > len(out) - var4:
                        out_off = len(out) - var4
                    out[var4 : var4 + out_off] = self.a[var5 + 1 : var5 + 1 + out_off]
                    out_off = out_off + var4
                return out_off
            var5 -= 1

    def h(self, out: bytearray, idx: int) -> Tuple[int, int]:
        # Port of NamePool.h(byte[] var1, int var2) => returns c(var4, var5)
        var9 = self.a
        if idx >= len(var9):
            return (0, 0)

        if var9[idx] != 0:
            var4 = self.c_decode(out, 0, idx)
        else:
            var4 = 0

        var7 = idx + 1
        var8 = len(self.a) - idx - 1
        var2 = var4
        var6 = var7
        var5 = var8
        if var8 > len(out) - var4:
            var5 = len(out) - var4
            var6 = var7
            var2 = var4

        while True:
            var4 = var6
            if var5 == 0:
                break
            var3 = self.a[var6]
            var4 = var6
            if (var3 & 0xE0) == 0:
                break
            var4 = var6
            if (var3 & 0xFF) >= 128:
                break
            var6 += 1
            out[var2] = var3
            var5 -= 1
            var2 += 1

        while True:
            if var4 >= len(var9):
                break
            var10 = var9[var4]
            if (var10 & 0xE0) == 0 or (var10 & 0xFF) >= 128:
                break
            var4 += 1

        var6 = var4 + 1
        var5 = var4
        if var6 < len(var9):
            var5 = var4
            if (var9[var6] & 0xF0) == 16:
                var5 = var6

        var4 = var2
        if var2 < len(out):
            out[var2] = 0
            var4 = var2 + 1

        return (var4, var5)

    def f_index(self) -> Optional[List[int]]:
        # Port of NamePool.f()
        if self.b is not None:
            return self.b
        if self.i() <= 64:
            return None

        # if (this.b == null && this.i() > 64) { this.b = new int[(this.c - 1) / 64]; ... }
        self.b = [0] * ((self.c - 1) // 64)
        var1 = len(self.a)
        var2 = 0
        var3 = 0
        var5 = 0
        while var1 > 0:
            var6 = var1
            var4 = var2
            var3 = var5
            if var2 >= 64:
                self.b[var5] = var1
                var4 = var2 - 64
                var3 = var5 + 1
                var6 = var1

            while True:
                var6 -= 1
                var7 = self.a[var6]
                if not ((var7 & 0xFF) < 128 and (var7 & 0xE0) != 0):
                    break

            var1 = var6
            if (var7 & 0xF0) == 16:
                var1 = var6 - 1

            var2 = var4 + 1
            var5 = var3
        return self.b

    def g_extract(self, out: bytearray, id_: int) -> int:
        # Port of NamePool.g(byte[] out, int id)
        if id_ >= self.i():
            return 0
        var3 = len(self.a)
        var2 = self.c - id_ - 1
        var4 = var2 % 64
        var5 = var2 // 64
        var2_local = var3
        var3_local = var4

        if var5 != 0:
            idxs = self.f_index()
            if idxs is None:
                raise ValueError("Internal error: expected index table")
            var2_local = idxs[var5 - 1]
            var3_local = var4

        while var3_local != 0:
            while True:
                var4 = var2_local - 1
                var6 = self.a[var4]
                if (var6 & 0xE0) == 0 or (var6 & 0xFF) >= 128:
                    var2_local = var4
                    if (var6 & 0xF0) == 16:
                        var2_local = var4 - 1
                    break
                var2_local = var4
            var3_local -= 1

        return self.h(out, var2_local - 1)[0]

    @dataclass(frozen=True)
    class _ARes:
        length: int
        flags: int

    def b_decode(self, out_buf: bytearray, encoded: bytes) -> _ARes:
        # Port of NamePool.b(byte[] var1, byte[] var2)
        var4 = 0
        var13 = 0
        var8 = -1
        var7 = -1
        var5 = var7
        var9 = 0
        var6 = var7

        var3 = 0
        for var4 in range(var9, len(encoded)):
            var10 = encoded[var4]
            if var10 == 0:
                break

            var9 = var3
            var11 = var13
            if var10 != 54:  # '6'
                if var10 != 72:  # 'H'
                    if var10 == 85:  # 'U'
                        var7 = var4
                        var8 = var3
                        var3 = var4 + 1
                else:
                    var5 = var4 + 1
                    var6 = var3
                    var3 = var5
            else:
                # while(var9 != var4) { ... }
                while var9 != var4:
                    var3 = self.l(encoded[var9]) & 0xFF
                    if var3 >= 97:
                        var3 -= 61
                    elif var3 >= 65:
                        var3 -= 55
                    else:
                        var3 -= 48
                    var11 |= 1 << var3
                    var9 += 1

                var3 = var9 + 1
                var13 = var11
                if len(out_buf) <= 0:
                    return NamePool._ARes(0, var13)

        # var3 = this.k(var1, 0, var2, var3, var4 - var3);
        # Note: in Java, var4 is the loop index at exit; here, var4 holds the last examined/terminal.
        length_decoded = self.k(out_buf, 0, encoded, var3, (var4 - var3))

        if var8 != -1 and length_decoded < len(out_buf):
            var4tmp = length_decoded + 1
            out_buf[length_decoded] = 64  # '@'
            length_decoded = var4tmp + self.k(out_buf, var4tmp, encoded, var8, (var7 - var8))

        var4_after = length_decoded
        if var6 != -1:
            length_decoded += self.k(out_buf, length_decoded, bytes([53, 78]), 0, 2)
            var4_after = length_decoded + self.k(out_buf, length_decoded, encoded, var6, (var5 - var6))

        return NamePool._ARes(var4_after, var13)

    def d(self, id_: int) -> Optional[NamePoolVirusName]:
        # Port of NamePool.d(int id)
        out_tmp = bytearray(200)
        if self.g_extract(out_tmp, id_) != 0:
            out_buf = bytearray(200)
            decoded = self.b_decode(out_buf, bytes(out_tmp))
            length = decoded.length
            if length != 0:
                name_bytes = bytes(out_buf[:length])
                return NamePoolVirusName(name_bytes=name_bytes, flags=decoded.flags)
        return None


# ----------------------------
# kb10 pattern extraction
# ----------------------------


@dataclass(frozen=True)
class KB10PatternRule:
    # pattern record id stored in db map
    pattern_record_id: int
    # shift byte stored in each pattern record header (used as "f()" in kb10.c)
    shift: int
    # compare length (g() in kb10.c)
    length: int
    # wildcard constant byte stored in kb10.c (h())
    wildcard_constant: int
    # compare bytes stored in kb10.c (from patterns blob)
    compare_bytes: bytes

    def is_exact(self) -> bool:
        return self.wildcard_constant == 0

    def logic_dict(self) -> Dict[str, object]:
        """
        Explain the matching semantics in terms of input bytes.

        In kb10.c:
          - exact: require (input[pos+i] == (compare[i] ^ 0xA5))
          - wildcard: for each i:
              if compare[i] == (wildcard_constant ^ 0xA5): allow any input byte
              else require inputByte == (compare[i] ^ 0xA5)

        (0xA5 == -91 lower 8 bits)
        """

        XOR = 0xA5
        wc_encoded = (self.wildcard_constant ^ XOR) & 0xFF

        wildcard_positions: List[int] = []
        expected_positions: Dict[str, str] = {}

        # compare_bytes are raw stored bytes; kb10 compares using XOR -91 against input bytes.
        for i, stored in enumerate(self.compare_bytes):
            stored_u = stored
            if self.is_exact():
                expected = stored_u ^ XOR
                expected_positions[str(i)] = f"0x{expected:02X}"
            else:
                if stored_u == wc_encoded:
                    wildcard_positions.append(i)
                else:
                    expected = stored_u ^ XOR
                    expected_positions[str(i)] = f"0x{expected:02X}"

        return {
            "match_type": "exact" if self.is_exact() else "wildcard",
            "shift": self.shift,
            "length": self.length,
            "wildcard_constant": f"0x{self.wildcard_constant:02X}",
            "wildcard_positions": wildcard_positions,
            "expected_positions": expected_positions,
            "compare_bytes_hex": self.compare_bytes.hex(),
        }


@dataclass(frozen=True)
class KB10Data:
    """
    Parsed kb10.a(FileMapper.b) state from db_*.map (STRINGS_BLOB section).
    """

    # Used as the scan limit in kb10.b(...) (a.e()).
    scan_limit: int
    # Bloom/filter bits (a.a()).
    bloom: bytes
    # Used as a mask in the rolling hash result (a.b()).
    bloom_mask: int
    # Group filter records bytes (a.c()).
    group_filter: bytes
    # Mask applied to candidate anchors to select group records (a.d()).
    group_mask: int
    # Pattern blob bytes (a.f()).
    patterns: bytes


def parse_map_section(map_bytes: bytes, section_counter: int) -> bytes:
    """
    Port of FileMapper.f/g section slicing.

    FileMapper uses:
      baseOffset = magicLen + 4 = 16
      each preceding section is stored as: [u32 section_len][section_len bytes]
      section content begins at (section_len_offset + 4)
    """
    if len(map_bytes) < 20:
        raise ValueError("map bytes too small")
    off = 16
    for _ in range(section_counter):
        if off + 4 > len(map_bytes):
            raise ValueError("map truncated while skipping sections")
        sec_len = u32_le(map_bytes, off)
        off += 4 + sec_len
    if off + 4 > len(map_bytes):
        raise ValueError("map truncated before section header")
    sec_len = u32_le(map_bytes, off)
    start = off + 4
    end = start + sec_len
    if end > len(map_bytes):
        raise ValueError("map truncated within section content")
    return map_bytes[start:end]


def detect_datafile_engine(map_bytes: bytes) -> str:
    magic = map_bytes[:12]
    m = magic.decode("ascii", errors="ignore")
    if "MS2+" in m:
        return "MULTI_STRING"
    if "ST1+" in m:
        return "SINGLE_STRING"
    return "UNKNOWN"


def _int32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


# Decompiled rq3.c(int) lookup uses rq3.b[] in Java. rq3.c(index) returns rq3.b[index].
RQ3_C_TABLE = [
    0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767,
    65535, 131071, 262143, 524287, 1048575, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
    0x1FFFFFF, 0x3FFFFFF, 0x7FFFFFF, 0xFFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF,
    0x7FFFFFFF,  # Integer.MAX_VALUE
    -1,
]


class Nq3:
    """
    Port of mobilesecurity/o/nq3.java (nq3.a/b/c).
    """

    def __init__(self, b: int, c: int, a_bytes: bytes):
        self.a = a_bytes
        self.b = b
        self.c = c

    def a_fn(self, n: int) -> int:
        # Port of nq3.a(int n)
        if n < 0:
            return -1
        if n > self.c:
            return -1

        b_self = self.b
        mult = n * b_self
        n3 = mult // 32
        n_rem = mult % 32
        n4 = 32 - n_rem

        def u32_at(word_index: int) -> int:
            return _chm_g_u32(self.a, word_index * 4) & 0xFFFFFFFF

        if b_self <= n4:
            word = u32_at(n3)
            mask = RQ3_C_TABLE[b_self] if 0 <= b_self < len(RQ3_C_TABLE) else 0
            mask_u = mask & 0xFFFFFFFF
            res_u = mask_u & (word >> n_rem)
            return _int32(res_u)

        # else: spans two words
        low = u32_at(n3)
        high = u32_at(n3 + 1)
        idx = b_self - n4
        mask = RQ3_C_TABLE[idx] if 0 <= idx < len(RQ3_C_TABLE) else 0
        mask_u = mask & 0xFFFFFFFF
        res_u = ((mask_u & high) << n4) | (low >> n_rem)
        return _int32(res_u)

    def b_value(self) -> int:
        return self.b

    def c_value(self) -> int:
        return self.c


class E2pA:
    """
    Port of e2p$a from mobilesecurity.
    """

    def __init__(self, nq3_a: Nq3, nq3_b: Nq3, nq3_c: Nq3):
        self.nq3_a = nq3_a
        self.nq3_b = nq3_b
        self.nq3_c = nq3_c
        shift = self.nq3_b.b_value() - 1
        self.d_mask = 1 << shift
        if self.d_mask == 0:
            raise ValueError("Invalid e2p group mask (d_mask=0)")

    def b_len(self) -> int:
        # e2p$a.b(): return nq3_a.c()
        return self.nq3_a.c_value()

    def c_threshold(self, n: int) -> int:
        # e2p$a.c(int n): return nq3_a.a(n)
        return self.nq3_a.a_fn(n)


class E2pAIter:
    """
    Port of e2p$a$a from mobilesecurity.
    """

    def __init__(self, parent: E2pA):
        self.c_parent = parent
        self.a = 0
        self.b = 0

    def a_ready(self) -> bool:
        return self.a != 0

    def c(self, leaf_id: int) -> None:
        self.a = 0
        self.b = 0

        mapped = self.c_parent.nq3_b.a_fn(leaf_id)
        if mapped == 0:
            return

        d = self.c_parent.d_mask
        mapped_u = mapped & 0xFFFFFFFF
        d_u = d & 0xFFFFFFFF

        if (mapped_u & d_u) != 0:
            # n &= ~d
            stripped = mapped_u & (~d_u & 0xFFFFFFFF)
            self.b = stripped
            self.a = self.c_parent.nq3_c.a_fn(stripped)
            return

        self.a = mapped_u

    def b_index(self) -> int:
        n_u = self.a & 0xFFFFFFFF
        d_u = self.c_parent.d_mask & 0xFFFFFFFF

        if (d_u & n_u) != 0:
            self.b = self.b + 1
            self.a = self.c_parent.nq3_c.a_fn(self.b)
        else:
            self.a = 0

        # return ~d & n
        idx_u = (~d_u & 0xFFFFFFFF) & n_u
        return idx_u


def parse_e2p_group_mapping(map_bytes: bytes, *, source_label: str) -> E2pA:
    """
    Parse STRING_GROUPS_BLOB (FileMapper.SectionType.STRING_GROUPS_BLOB, counter=1)
    into E2pA using three concatenated nq3 blocks.
    """
    section_bytes = parse_map_section(map_bytes, 1)
    cur = ByteCursor(section_bytes)
    # nq3 blocks: [b(u32)][c(u32)][nLen(u32)][bytes(nLen)]
    def read_nq3() -> Nq3:
        cur.require(12, f"{source_label}: nq3 header")
        b = cur.read_u32(f"{source_label}: nq3.b")
        c = cur.read_u32(f"{source_label}: nq3.c")
        nlen = cur.read_u32(f"{source_label}: nq3.aLen")
        if nlen < 0 or cur.remaining() < nlen:
            raise ValueError(f"{source_label}: nq3 data truncated (nlen={nlen}, remaining={cur.remaining()})")
        a_bytes = cur.read_bytes(nlen, f"{source_label}: nq3.a")
        return Nq3(b=b, c=c, a_bytes=a_bytes)

    nq3_a = read_nq3()
    nq3_b = read_nq3()
    nq3_c = read_nq3()
    return E2pA(nq3_a=nq3_a, nq3_b=nq3_b, nq3_c=nq3_c)


def e2p_promote(leaf_pattern_ids: List[int], e2p_a: E2pA) -> List[int]:
    """
    Port of e2p.b() promotion:
      - counters[dIndex] increments for each leaf hit via E2pAIter
      - final selection: counters[idx] >= threshold(idx)
    Returns selected NamePool IDs (idx-1).
    """
    d_len = e2p_a.b_len()
    d_counters = [0] * d_len
    it = E2pAIter(e2p_a)

    for leaf_id in leaf_pattern_ids:
        it.c(leaf_id)
        while it.a_ready():
            idx = it.b_index()
            if 0 <= idx < d_len:
                cur = d_counters[idx]
                if cur != 32767:
                    d_counters[idx] = cur + 1
            # loop continues; it.c/it.b() state advances inside b_index()

    selected: List[int] = []
    for idx in range(1, d_len):
        cnt = d_counters[idx]
        if cnt != 0:
            thr = e2p_a.c_threshold(idx)
            if thr != 0 and cnt >= thr:
                selected.append(idx - 1)
            d_counters[idx] = 0
    return selected


def e2p_counters_after_leaf_scan(leaf_pattern_ids: List[int], e2p_a: E2pA) -> List[Tuple[int, int, int]]:
    """
    After feeding the same leaf id sequence as ``e2p_promote``, return one row per e2p slot
    ``idx`` (1 .. d_len-1) with non-zero counter: ``(idx, counter, threshold)``.

    Used for debug: explain why MULTI_STRING promotion did or did not yield detections
    (threshold 0 means that slot never promotes; counter < threshold means not enough hits).
    """
    d_len = e2p_a.b_len()
    d_counters = [0] * d_len
    it = E2pAIter(e2p_a)

    for leaf_id in leaf_pattern_ids:
        it.c(leaf_id)
        while it.a_ready():
            idx = it.b_index()
            if 0 <= idx < d_len:
                cur = d_counters[idx]
                if cur != 32767:
                    d_counters[idx] = cur + 1

    rows: List[Tuple[int, int, int]] = []
    for idx in range(1, d_len):
        cnt = d_counters[idx]
        if cnt != 0:
            rows.append((idx, cnt, e2p_a.c_threshold(idx)))
    return rows


def e2p_promote_single_leaf(leaf_pattern_id: int, e2p_a: E2pA) -> List[int]:
    """
    Much faster approximation of e2p.b() for the special case where only
    one leaf pattern id is present in the scan result.

    It computes which d[] indices get a +1 increment from that single leaf,
    then selects those indices where threshold(idx) != 0 and threshold(idx) <= 1.
    """
    d_len = e2p_a.b_len()
    it = E2pAIter(e2p_a)
    inc_idxs = set()

    it.c(leaf_pattern_id)
    while it.a_ready():
        idx = it.b_index()
        if 0 <= idx < d_len:
            inc_idxs.add(idx)

    selected: List[int] = []
    for idx in inc_idxs:
        thr = e2p_a.c_threshold(idx)
        if thr != 0 and 1 >= thr:
            selected.append(idx - 1)
    return selected


def _chm_g_u32(buf: bytes, off: int) -> int:
    # Decompiled chm.g(): u32 little-endian
    if off < 0 or off + 4 > len(buf):
        raise ValueError(f"chm_g_u32 out of bounds: off={off} len={len(buf)}")
    return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8) | ((buf[off + 2] & 0xFF) << 16) | ((buf[off + 3] & 0xFF) << 24)


def _chm_h_u32(buf: bytes, off: int, nbytes: int) -> int:
    # Decompiled chm.h(): little-endian integer from 0..4 bytes.
    if nbytes == 0:
        return 0
    if off < 0 or off + nbytes > len(buf):
        raise ValueError(f"chm_h_u32 out of bounds: off={off} nbytes={nbytes} len={len(buf)}")
    if nbytes == 1:
        return buf[off] & 0xFF
    if nbytes == 2:
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8)
    if nbytes == 3:
        return (buf[off] & 0xFF) | ((buf[off + 1] & 0xFF) << 8) | ((buf[off + 2] & 0xFF) << 16)
    if nbytes == 4:
        return _chm_g_u32(buf, off)
    raise ValueError(f"Invalid nbytes for chm.h: {nbytes}")


def _sbyte(b: int) -> int:
    # Java byte sign extension.
    return b - 256 if b >= 128 else b


def parse_kb10_data_from_map(map_bytes: bytes, *, source_label: str = "kb10") -> KB10Data:
    """
    Port of kb10.a(FileMapper.b) initialization:
      - FileMapper already slices STRINGS_BLOB section.
      - In our extractor, we parse the kb10.a header within that section.
    """
    if len(map_bytes) < 20:
        raise ValueError(f"{source_label}: map file too small")

    magic_len = 12
    expected_u32 = u32_le(map_bytes, magic_len)
    if expected_u32 != len(map_bytes) - magic_len - 4:
        raise ValueError(f"{source_label}: invalid map integrity check (size mismatch)")

    section0_start = magic_len + 4  # 16
    section0_len = u32_le(map_bytes, section0_start)
    content_start = section0_start + 4
    content_end = content_start + section0_len
    if content_end > len(map_bytes):
        raise ValueError(f"{source_label}: truncated STRINGS_BLOB section")

    strings_blob = map_bytes[content_start:content_end]
    cur = ByteCursor(strings_blob)
    cur.require(40, f"{source_label}: kb10 header")

    scan_limit = cur.read_u32(f"{source_label}: a.scanLimit")  # a = var1.c()
    scan_limit2 = cur.read_u32(f"{source_label}: a.b")  # b = var1.c()  (kb10.b uses a.e() == this.b)
    bloom_len_bytes = cur.read_u32(f"{source_label}: bloom_len")
    group_len_bytes = cur.read_u32(f"{source_label}: group_len")
    patterns_len_bytes = cur.read_u32(f"{source_label}: patterns_len")
    var7 = cur.read_u32(f"{source_label}: var7")
    skip_var2 = cur.read_u32(f"{source_label}: skip_var2")
    skip_var4 = cur.read_u32(f"{source_label}: skip_var4")
    skip_var3 = cur.read_u32(f"{source_label}: skip_var3")

    # Java does: var1.a(4) => cursor.skip(4)
    cur.skip(4, f"{source_label}: header skip4")

    bloom_mask = bloom_len_bytes * 8 - 1
    if bloom_len_bytes <= 0 or not is_power_of_two(bloom_len_bytes):
        raise ValueError(f"{source_label}: invalid bloom_len={bloom_len_bytes}")
    bloom = cur.read_bytes(bloom_len_bytes, f"{source_label}: bloom")

    if group_len_bytes % 16 != 0:
        raise ValueError(f"{source_label}: group_len not multiple of 16: {group_len_bytes}")
    group_units = group_len_bytes // 16
    group_mask = group_units - 1
    if not is_power_of_two(group_units):
        raise ValueError(f"{source_label}: invalid group_units={group_units}")
    group_filter = cur.read_bytes(group_len_bytes, f"{source_label}: group_filter")

    if var7 <= 0 or patterns_len_bytes <= 0:
        raise ValueError(f"{source_label}: invalid patterns sizes var7={var7}, patterns_len={patterns_len_bytes}")
    patterns = cur.read_bytes(patterns_len_bytes, f"{source_label}: patterns_blob")

    # The ctor skips: var1.a(var2 + var4 + var3)
    # We only parse what we need; ensure the file isn't truncated.
    if skip_var2 + skip_var4 + skip_var3 > 0:
        if cur.remaining() < (skip_var2 + skip_var4 + skip_var3):
            raise ValueError(f"{source_label}: truncated after patterns")
        cur.skip(skip_var2 + skip_var4 + skip_var3, f"{source_label}: tail skip")

    return KB10Data(
        scan_limit=scan_limit2,  # kb10.a.e() returns this.b (second u32)
        bloom=bloom,
        bloom_mask=bloom_mask,
        group_filter=group_filter,
        group_mask=group_mask,
        patterns=patterns,
    )


def kb10_scan_matches(
    *,
    data: KB10Data,
    input_bytes: bytes,
    max_bytes: Optional[int] = None,
    target_pattern_id: Optional[int] = None,
    out_stats: Optional[Dict[str, Any]] = None,
    out_hit_records: Optional[List[Dict[str, Any]]] = None,
    hit_record_limit: int = 256,
) -> List[Tuple[int, int]]:
    """
    Simulate kb10.b(byte[], int) + kb10.c matching.

    Returns list of tuples:
      (pattern_record_id, anchor_offset_used_for_c2.a)

    If ``out_stats`` is a dict, it is filled with scan pipeline counters (bloom / u32 gate / PatternC tries),
    useful for ``--debug`` tooling. Keys are stable for scripting.

    If ``out_hit_records`` is a list, each successful PatternC match appends a dict with
    ``pattern_record_id``, ``kb10_anchor``, ``input_start_offset``, ``compare_len``,
    ``input_bytes_hex`` (raw file bytes under comparison), ``match_mode`` (``exact`` / ``wildcard``).
    At most ``hit_record_limit`` rows are stored; if truncated, ``out_stats['hit_records_capped']`` is set.
    """
    if input_bytes is None:
        return []
    n = len(input_bytes)
    if max_bytes is not None:
        n = min(n, max_bytes)
        input_bytes = input_bytes[:n]

    if input_bytes is None or len(input_bytes) < 4 or n < 4:
        if out_stats is not None:
            out_stats["scan_early_exit_short_input"] = 1
            out_stats["scan_buffer_len"] = len(input_bytes) if input_bytes else 0
        return []

    # This corresponds to kb10.b early-return checks and then scanning on first n bytes.
    n2 = n - 4
    n3 = min(data.scan_limit, n2)
    bloom = data.bloom
    bloom_mask = data.bloom_mask
    group_mask = data.group_mask

    def dbg(key: str, delta: int = 1) -> None:
        if out_stats is not None:
            out_stats[key] = out_stats.get(key, 0) + delta

    if out_stats is not None:
        out_stats["scan_buffer_len"] = n
        out_stats["scan_limit_from_map"] = int(data.scan_limit)
        out_stats["n2"] = n2
        out_stats["n3_phase1_last_n_cur"] = n3
        out_stats["bloom_len_bytes"] = len(bloom)
        out_stats["group_filter_len_bytes"] = len(data.group_filter)

    # rolling hash: int n6 = chm.h(input,0,3) << 8;
    n6 = _chm_h_u32(input_bytes, 0, 3) << 8

    # Results
    matches: List[Tuple[int, int]] = []

    # Pattern matcher c2 wrapper (stateful via ptr)
    patterns = data.patterns

    class GroupB:
        def __init__(self, group_filter: bytes):
            self.group = group_filter
            self.off = 0

        def a(self) -> int:
            # chm.g(group, b + 12)
            return _chm_g_u32(self.group, self.off + 12)

        def b(self) -> int:
            # chm.h(group, b, 3)
            return _chm_h_u32(self.group, self.off, 3)

        def c(self) -> int:
            # chm.g(group, b + 4)
            return _chm_g_u32(self.group, self.off + 4)

        def d(self) -> int:
            # byte at group[b+3] sign-extended
            return _sbyte(self.group[self.off + 3])

        def e(self) -> int:
            # chm.g(group, b + 8)
            return _chm_g_u32(self.group, self.off + 8)

        def f(self, group_index: int) -> None:
            # b = group_index * 16
            self.off = group_index * 16

    class PatternC:
        def __init__(self, patterns_blob: bytes):
            self.a = patterns_blob
            self.b = 0  # pointer into patterns blob

        def e(self) -> int:
            return _chm_g_u32(self.a, self.b)

        def f(self) -> int:
            return self.a[self.b + 7] & 0xFF

        def g(self) -> int:
            return self.a[self.b + 6] & 0xFF

        def h(self) -> int:
            return self.a[self.b + 5]  # raw byte

        def i(self) -> bool:
            return (self.a[self.b + 5] & 0xFF) == 0

        def d(self) -> int:
            return self.b + 8

        def j(self) -> None:
            self.b = self.d() + self.g()

        def k(self, ptr: int) -> None:
            self.b = ptr

        def a_match(self, buf: bytes, anchor: int) -> bool:
            if self.i():
                return self.b_exact(buf, anchor)
            return self.c_wild(buf, anchor)

        def b_exact(self, buf: bytes, anchor: int) -> bool:
            ln = self.g()
            pat_start = self.d()
            input_idx = anchor - self.f()
            for k in range(ln):
                pat_byte = _sbyte(self.a[pat_start + k])
                in_byte = _sbyte(buf[input_idx + k])
                if (pat_byte ^ -91) != in_byte:
                    return False
            return True

        def c_wild(self, buf: bytes, anchor: int) -> bool:
            ln = self.g()
            pat_start = self.d()
            input_idx = anchor - self.f()
            wild = _sbyte(self.h())
            for k in range(ln):
                stored = _sbyte(self.a[pat_start + k])
                in_b = _sbyte(buf[input_idx + k])
                if (wild ^ -91) != stored and (in_b ^ -91) != stored:
                    return False
            return True

    def urshift(x: int, r: int) -> int:
        return (x & 0xFFFFFFFF) >> r

    def chm_g_safe(buf: bytes, off: int) -> Optional[int]:
        if off < 0 or off + 4 > len(buf):
            return None
        return _chm_g_u32(buf, off)

    def boundary_ok(n1: int, n2len: int, n3len: int) -> bool:
        # Port of kb10.c(int var1, int var2, int var3)
        if n3len < 0 or n1 < 0:
            return False
        return n3len >= n1 + n2len

    _hit_cap = max(0, int(hit_record_limit))

    def add_match(c2: PatternC, anchor: int) -> None:
        pid = c2.e()
        if target_pattern_id is not None and pid != target_pattern_id:
            return
        matches.append((pid, anchor))
        if out_hit_records is not None and _hit_cap > 0:
            if len(out_hit_records) >= _hit_cap:
                if out_stats is not None:
                    out_stats["hit_records_capped"] = 1
                return
            input_idx = anchor - c2.f()
            ln = c2.g()
            wild = not c2.i()
            rec: Dict[str, Any] = {
                "pattern_record_id": int(pid),
                "kb10_anchor": int(anchor),
                "input_start_offset": int(input_idx),
                "compare_len": int(ln),
                "match_mode": "wildcard" if wild else "exact",
            }
            if boundary_ok(input_idx, ln, n8) and input_idx >= 0 and input_idx + ln <= len(input_bytes):
                rec["input_bytes_hex"] = input_bytes[input_idx : input_idx + ln].hex()
            else:
                rec["input_bytes_hex"] = ""
                rec["note"] = "unexpected_bounds_after_match"
            out_hit_records.append(rec)

    c2 = PatternC(patterns)
    b2 = GroupB(data.group_filter)

    # First loop: kb10.b(...) uses e(...) for region 0..n3
    n7_var = 0
    n8 = n  # original input length used in boundary checks
    for n_cur in range(0, n3 + 1):
        dbg("phase1_n_cur_positions")
        # n6 = n6>>>8 | input[n_cur+3] << 24;
        n6 = (urshift(n6, 8) | ((input_bytes[n_cur + 3] & 0xFF) << 24)) & 0xFFFFFFFF
        n7_var = (((urshift(n6, 17) + n6) & 0xFFFFFFFF) & bloom_mask)  # candidate anchor
        byte_index = n7_var >> 3
        bit = 1 << (n7_var & 7)
        if byte_index < 0 or byte_index >= len(bloom):
            dbg("bloom_bad_index")
            continue
        if (bloom[byte_index] & 0xFF) & bit == 0:
            dbg("bloom_filter_miss")
            continue
        dbg("bloom_filter_pass")
        b2.f(n7_var & group_mask)
        # kb10.e(c2,b2,input,n8,n_cur)
        anchor = n_cur
        n3_offset = b2.d() + anchor
        if not boundary_ok(n3_offset, 4, n8):
            dbg("u32_read_bounds_fail")
            continue
        hv = chm_g_safe(input_bytes, n3_offset)
        if hv is None:
            dbg("u32_read_bounds_fail")
            continue
        if ((hv ^ b2.e()) & b2.c()) != 0:
            dbg("u32_group_gate_miss")
            continue
        dbg("u32_group_gate_pass")

        # Now test pattern at anchor and its alternatives
        c2.k(b2.a())
        # boundary check and match for current pattern record
        if boundary_ok(anchor - c2.f(), c2.g(), n8):
            dbg("pattern_compare_try")
            if c2.a_match(input_bytes, anchor):
                dbg("pattern_compare_hit")
                add_match(c2, anchor)
        for _i in range(b2.b() - 1, 0, -1):
            c2.j()
            if boundary_ok(anchor - c2.f(), c2.g(), n8):
                dbg("pattern_compare_try")
                if c2.a_match(input_bytes, anchor):
                    dbg("pattern_compare_hit")
                    add_match(c2, anchor)

    # Second while(true) and trailing loop are mostly to avoid repeated boundary checks.
    # Port directly to keep exact semantics.
    n9 = data.scan_limit
    n_cur = n3 + 1
    # replicate Java variables: after for loop, n is n_cur (last n+1)
    while True:
        n3_saved = n6
        n7_saved = n_cur
        if n_cur > n2 - n9:
            break
        dbg("phase2_n_cur_positions")
        # update rolling hash using current n_cur
        n6 = (urshift(n6, 8) | ((input_bytes[n_cur + 3] & 0xFF) << 24)) & 0xFFFFFFFF
        n7_var = (((urshift(n6, 17) + n6) & 0xFFFFFFFF) & bloom_mask)
        byte_index = n7_var >> 3
        bit = 1 << (n7_var & 7)
        if byte_index >= 0 and byte_index < len(bloom) and (bloom[byte_index] & 0xFF) & bit != 0:
            dbg("bloom_filter_pass")
            b2.f(n7_var & group_mask)
            # kb10.d(c2,b2,input, n_cur)
            anchor = n_cur
            n3_offset = b2.d() + anchor
            hv = chm_g_safe(input_bytes, n3_offset)
            if hv is None:
                dbg("u32_read_bounds_fail")
            elif ((hv ^ b2.e()) & b2.c()) != 0:
                dbg("u32_group_gate_miss")
            else:
                dbg("u32_group_gate_pass")
                c2.k(b2.a())
                dbg("pattern_compare_try")
                if c2.a_match(input_bytes, anchor):
                    dbg("pattern_compare_hit")
                    add_match(c2, anchor)
                for _i in range(b2.b() - 1, 0, -1):
                    c2.j()
                    dbg("pattern_compare_try")
                    if c2.a_match(input_bytes, anchor):
                        dbg("pattern_compare_hit")
                        add_match(c2, anchor)
        else:
            dbg("bloom_filter_miss")
        n_cur += 1

    # Tail loop: while (n7 <= n2)
    # At break, n7_saved holds last anchor candidate n_cur from previous assignment.
    n7_tail = n7_saved
    n3_tail = n3_saved
    while n7_tail <= n2:
        dbg("phase3_n_cur_positions")
        # n3 = n3>>>8 | input[n7+3]<<24
        n3_tail = (urshift(n3_tail, 8) | ((input_bytes[n7_tail + 3] & 0xFF) << 24)) & 0xFFFFFFFF
        n_candidate = (((urshift(n3_tail, 17) + n3_tail) & 0xFFFFFFFF) & bloom_mask)
        byte_index = n_candidate >> 3
        bit = 1 << (n_candidate & 7)
        if byte_index >= 0 and byte_index < len(bloom) and (bloom[byte_index] & 0xFF) & bit != 0:
            dbg("bloom_filter_pass")
            b2.f(n_candidate & group_mask)
            anchor = n7_tail
            n3_offset = b2.d() + anchor
            if boundary_ok(n3_offset, 4, n8):
                hv = chm_g_safe(input_bytes, n3_offset)
                if hv is None:
                    dbg("u32_read_bounds_fail")
                elif ((hv ^ b2.e()) & b2.c()) != 0:
                    dbg("u32_group_gate_miss")
                else:
                    dbg("u32_group_gate_pass")
                    c2.k(b2.a())
                    if boundary_ok(anchor - c2.f(), c2.g(), n8):
                        dbg("pattern_compare_try")
                        if c2.a_match(input_bytes, anchor):
                            dbg("pattern_compare_hit")
                            add_match(c2, anchor)
                    for _i in range(b2.b() - 1, 0, -1):
                        c2.j()
                        if boundary_ok(anchor - c2.f(), c2.g(), n8):
                            dbg("pattern_compare_try")
                            if c2.a_match(input_bytes, anchor):
                                dbg("pattern_compare_hit")
                                add_match(c2, anchor)
            else:
                dbg("u32_read_bounds_fail")
        else:
            dbg("bloom_filter_miss")
        n7_tail += 1

    if out_stats is not None:
        out_stats["raw_match_tuples"] = len(matches)
        out_stats["unique_pattern_record_ids"] = len({pid for pid, _ in matches})
        if out_hit_records is not None:
            out_stats["hit_records_stored"] = len(out_hit_records)

    return matches


def parse_kb10_strings_blob(map_bytes: bytes) -> bytes:
    """
    Parse db_*.map and extract the kb10 pattern "g" byte blob from the first section (STRINGS_BLOB).

    Java mapping:
      FileMapper:
        magicLen = DataFileType.getMagicLength() (12 here)
        sectionStart = magicLen + 4  (magicLen+4 = 16)
        section0 length at offset sectionStart
        section0 content at sectionStart+4

      kb10.a ctor:
        reads 9 u32 ints, skips 4 bytes, then reads:
          bloom_len bytes (unused)
          group_len bytes (unused)
          pattern_len bytes (patterns blob)
        skips var2+var4+var3 bytes after patterns
    """

    if len(map_bytes) < 20:
        raise ValueError("map file too small")

    magic_len = 12  # all DataFileType magics in this decompiled code are 12 bytes
    magic = map_bytes[:magic_len]

    # validate integrity like FileMapper.b(byte[])
    expected_u32 = u32_le(map_bytes, magic_len)
    if expected_u32 != len(map_bytes) - magic_len - 4:
        raise ValueError("Invalid map integrity check (size mismatch)")

    section0_start = magic_len + 4  # 16
    section0_len = u32_le(map_bytes, section0_start)
    section0_content_start = section0_start + 4
    section0_content_end = section0_content_start + section0_len
    if section0_content_end > len(map_bytes):
        raise ValueError("Truncated STRINGS_BLOB section")

    strings_blob = map_bytes[section0_content_start:section0_content_end]

    cur = ByteCursor(strings_blob)
    if cur.remaining() < 40:
        raise ValueError("STRINGS_BLOB too small for kb10 header")

    # Port kb10.a constructor initial int reads:
    _a0 = cur.read_u32("kb10.header.a0")
    _b0 = cur.read_u32("kb10.header.b0")
    bloom_len = cur.read_u32("kb10.header.bloom_len")
    group_len = cur.read_u32("kb10.header.group_len")
    pattern_len = cur.read_u32("kb10.header.pattern_len")
    unk_var7 = cur.read_u32("kb10.header.unk_var7")
    skip_var2 = cur.read_u32("kb10.header.skip_var2")
    skip_var4 = cur.read_u32("kb10.header.skip_var4")
    skip_var3 = cur.read_u32("kb10.header.skip_var3")
    cur.skip(4, "kb10.header.skip4")

    if bloom_len <= 0 or not is_power_of_two(bloom_len) or cur.remaining() < bloom_len:
        raise ValueError(f"Invalid bloom_len={bloom_len}")
    _bloom = cur.read_bytes(bloom_len, "kb10.bloom")

    if group_len % 16 != 0:
        raise ValueError(f"Invalid group_len (not multiple 16): {group_len}")
    group_units = group_len // 16
    if not is_power_of_two(group_units) or cur.remaining() < group_len:
        raise ValueError(f"Invalid group_units={group_units} or truncated group data")
    _group = cur.read_bytes(group_len, "kb10.group")

    if unk_var7 <= 0 or pattern_len <= 0 or cur.remaining() < pattern_len:
        raise ValueError("Invalid patterns blob sizes")
    patterns_blob = cur.read_bytes(pattern_len, "kb10.patterns")

    # skip remaining bytes as the ctor does
    cur.skip(skip_var2 + skip_var4 + skip_var3, "kb10.post-pattern skip")
    return patterns_blob


def parse_kb10_pattern_records(patterns_blob: bytes) -> List[KB10PatternRule]:
    """
    Port of kb10.c decoding approach:
      - each pattern record begins with:
          u32 record_id (little-endian)
          byte @ +4 (unused in match logic)
          byte wildcard_constant (h())
          byte length (g())
          byte shift (f())
          compare bytes length bytes at +8
    """
    XOR = 0xA5
    del XOR  # (kept for clarity)

    out: List[KB10PatternRule] = []
    pos = 0
    n = len(patterns_blob)
    while True:
        if pos + 8 > n:
            break
        rec_id = u32_le(patterns_blob, pos)
        wildcard_constant = patterns_blob[pos + 5]
        length = patterns_blob[pos + 6]
        shift = patterns_blob[pos + 7]
        cmp_start = pos + 8
        cmp_end = cmp_start + length
        if cmp_end > n:
            # corrupted/truncated record
            break
        compare_bytes = patterns_blob[cmp_start:cmp_end]
        out.append(
            KB10PatternRule(
                pattern_record_id=rec_id,
                shift=shift,
                length=length,
                wildcard_constant=wildcard_constant,
                compare_bytes=compare_bytes,
            )
        )
        pos = cmp_end
    return out


# ----------------------------
# Main: build mappings
# ----------------------------


def load_rules_from_db(
    nmp_path: Path,
    map_path: Path,
    source_label: str,
    max_rules: Optional[int] = None,
) -> Dict[str, List[Dict[str, object]]]:
    map_bytes = map_path.read_bytes()
    engine_type = detect_datafile_engine(map_bytes)

    np = NamePool(nmp_path.read_bytes())
    name_count = np.i()
    if name_count <= 0:
        raise ValueError(f"{source_label}: NamePool has invalid count={name_count}")

    patterns_blob = parse_kb10_strings_blob(map_bytes)
    patterns = parse_kb10_pattern_records(patterns_blob)

    name_cache: Dict[int, Optional[NamePoolVirusName]] = {}
    results: Dict[str, List[Dict[str, object]]] = {}
    emitted_count = 0

    # MULTI_STRING maps use e2p promotion (STRING_GROUPS_BLOB) on top of kb10 leaf patterns.
    # For JSON generation we use a best-effort mapping that assumes the scan result contains
    # only the current leaf pattern id (counter d[idx] becomes 1 for indices affected by that leaf).
    if engine_type == "MULTI_STRING":
        e2p_a = parse_e2p_group_mapping(map_bytes, source_label=source_label)

        def get_vn(name_id: int) -> Optional[NamePoolVirusName]:
            if name_id not in name_cache:
                name_cache[name_id] = np.d(name_id)
            return name_cache[name_id]

        for pr in patterns:
            leaf_id = pr.pattern_record_id
            selected_multi_ids = e2p_promote_single_leaf(leaf_id, e2p_a)
            if not selected_multi_ids:
                continue

            xor_key = 0xA5
            real_compare_value = bytes([(b ^ xor_key) & 0xFF for b in pr.compare_bytes]).hex()

            for multi_name_id in selected_multi_ids:
                if multi_name_id < 0 or multi_name_id >= name_count:
                    continue
                vn = get_vn(multi_name_id)
                if vn is None:
                    continue

                name = vn.decode_name()
                rule = pr.logic_dict()
                rule["pattern_record_id"] = leaf_id
                rule["name_id"] = multi_name_id
                rule["flags_raw"] = vn.flags
                rule["real_compare_value"] = real_compare_value
                rule["flags"] = {
                    "FLAG_COM": bool(vn.flags & 1),
                    "FLAG_ITW": bool(vn.flags & 512),
                    "FLAG_NEW_DETECTION": bool(vn.flags & 0x01000000),
                }
                results.setdefault(name, []).append(rule)
                emitted_count += 1
                if max_rules is not None and emitted_count >= max_rules:
                    break
            if max_rules is not None and emitted_count >= max_rules:
                break

        return results

    # SINGLE_STRING: lhz direct-signatures. Here pattern_record_id maps to NamePool id:
    #   namePoolId = pattern_record_id - 1
    for pr in patterns:
        rec_id = pr.pattern_record_id
        if rec_id < 1 or rec_id > name_count:
            continue
        name_id = rec_id - 1

        if name_id not in name_cache:
            name_cache[name_id] = np.d(name_id)
        vn = name_cache[name_id]
        if vn is None:
            continue

        name = vn.decode_name()
        rule = pr.logic_dict()
        rule["pattern_record_id"] = rec_id
        rule["name_id"] = name_id
        rule["flags_raw"] = vn.flags

        rule["flags"] = {
            "FLAG_COM": bool(vn.flags & 1),
            "FLAG_ITW": bool(vn.flags & 512),
            "FLAG_NEW_DETECTION": bool(vn.flags & 0x01000000),
        }

        xor_key = 0xA5
        rule["real_compare_value"] = bytes([(b ^ xor_key) & 0xFF for b in pr.compare_bytes]).hex()

        results.setdefault(name, []).append(rule)
        emitted_count += 1
        if max_rules is not None and emitted_count >= max_rules:
            break

    return results


def _pick_db_map(assets_dir: Path, prefix: str) -> Path:
    """``.map`` only; ``.sig`` is desktop engine (not this pipeline)."""
    p_map = assets_dir / f"{prefix}.map"
    if p_map.exists():
        return p_map
    raise FileNotFoundError(f"Missing {prefix}.map under {assets_dir}")


def discover_assets_db_stems(assets_dir: Path) -> List[str]:
    """All ``db_*.nmp`` with a sibling ``.map``."""
    if not assets_dir.is_dir():
        return []
    out: List[str] = []
    for nmp in sorted(assets_dir.glob("db_*.nmp")):
        stem = nmp.stem
        if (assets_dir / f"{stem}.map").exists():
            out.append(stem)
    return out


def resolve_scan_engine_paths(assets_dir: Path, scan_engine: str) -> Tuple[Path, Path, str]:
    """
    Returns ``(nmp_path, map_path, stem)`` for ``--scan-engine`` / ``--dump-pattern-id`` context.
    Accepts DEX, ELFA, ``db_foo``, or short name ``foo`` → ``db_foo``.
    """
    raw = scan_engine.strip()
    upper = raw.upper()
    if upper == "DEX":
        stem = "db_dex"
    elif upper == "ELFA":
        stem = "db_elfa"
    elif raw.lower().startswith("db_"):
        stem = raw
    else:
        stem = f"db_{raw.lower()}"
    nmp = assets_dir / f"{stem}.nmp"
    if not nmp.exists():
        raise FileNotFoundError(f"Missing {nmp}")
    return nmp, _pick_db_map(assets_dir, stem), stem


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("avast_db_rules.json"))
    ap.add_argument("--max-rules", type=int, default=0, help="0=all; otherwise cap total emitted rules")
    ap.add_argument("--scan-file", type=Path, default=None, help="If provided, simulate kb10 scan on this file (ELFA or DEX).")
    ap.add_argument(
        "--scan-engine",
        type=str,
        default="ELFA",
        help="Which db_* pair: DEX, ELFA, db_<name>, or short <name> (→ db_<name>).",
    )
    ap.add_argument("--scan-max-bytes", type=int, default=8388608, help="Max input bytes to scan (hm60 limits to 8MB).")
    ap.add_argument("--target-pattern-id", type=int, default=None, help="Optional: only report matches for this pattern_record_id.")
    ap.add_argument("--dump-pattern-id", type=int, default=None, help="Print decoded rule details for this pattern_record_id (no scan).")
    args = ap.parse_args()

    max_rules = None if args.max_rules == 0 else args.max_rules

    def dump_pattern(pattern_id: int, engine: str) -> None:
        _nmp, map_path, stem = resolve_scan_engine_paths(args.assets_dir, engine)
        map_bytes = map_path.read_bytes()
        patterns_blob = parse_kb10_strings_blob(map_bytes)
        rules = parse_kb10_pattern_records(patterns_blob)
        found = None
        for r in rules:
            if r.pattern_record_id == pattern_id:
                found = r
                break
        if found is None:
            raise SystemExit(f"pattern_record_id={pattern_id} not found in {stem} map")
        xor_key = 0xA5
        compare_bytes = found.compare_bytes
        expected_input = bytes([(b ^ xor_key) & 0xFF for b in compare_bytes])
        print(f"[+] {stem} pattern_record_id={pattern_id}")
        print(f"    match_type: {found.logic_dict()['match_type']}")
        print(f"    shift: {found.shift}")
        print(f"    length: {found.length}")
        print(f"    wildcard_constant: 0x{found.wildcard_constant:02X}")
        print(f"    compare_bytes_hex (DB): {compare_bytes.hex()}")
        print(f"    expected_input_bytes_hex (at file offset kb10_anchor - shift): {expected_input.hex()}")

    if args.dump_pattern_id is not None:
        dump_pattern(args.dump_pattern_id, args.scan_engine)
        if args.scan_file is None:
            return

    # Scan mode: decode just what we need for engine simulation.
    if args.scan_file is not None:
        nmp_path, map_path, stem = resolve_scan_engine_paths(args.assets_dir, args.scan_engine)

        map_bytes = map_path.read_bytes()
        engine_type = detect_datafile_engine(map_bytes)

        # Stage 1: kb10 leaf matches
        kb10_data = parse_kb10_data_from_map(map_bytes, source_label=stem)
        input_bytes = args.scan_file.read_bytes()
        matches = kb10_scan_matches(
            data=kb10_data,
            input_bytes=input_bytes,
            max_bytes=args.scan_max_bytes,
            target_pattern_id=None,  # leaf stage: collect all, then promote
        )
        leaf_ids = sorted({pid for pid, _anchor in matches})

        np = NamePool(nmp_path.read_bytes())

        target_leaf = args.target_pattern_id
        if target_leaf is not None:
            print(f"[+] Target leaf pattern id={target_leaf} present={target_leaf in leaf_ids}")

        # Stage 2: if map is MULTI_STRING, apply e2p promotion (kb10 -> e2p -> final virus names)
        if engine_type == "MULTI_STRING":
            e2p_a = parse_e2p_group_mapping(map_bytes, source_label=stem)
            selected_multi_ids = e2p_promote(leaf_ids, e2p_a)
            selected_names = []
            for mid in selected_multi_ids:
                vn = np.d(mid)
                selected_names.append(vn.decode_name() if vn is not None else f"UNKNOWN_NAME_ID_{mid}")

            print(
                f"[+] kb10 leaf hits={len(leaf_ids)}; e2p promoted multi-signatures={len(selected_multi_ids)}; "
                f"unique final names={len(set(selected_names))}"
            )
            for name in sorted(set(selected_names))[:50]:
                print(f"[*] {name}")
        else:
            # SINGLE_STRING: kb10 leaf pattern ids map directly to NamePool id via (pid - 1)
            selected_ids = [(pid - 1) for pid in leaf_ids if pid >= 1]
            selected_names = []
            for sid in selected_ids:
                vn = np.d(sid)
                selected_names.append(vn.decode_name() if vn is not None else f"UNKNOWN_NAME_ID_{sid}")

            print(
                f"[+] kb10 leaf hits={len(leaf_ids)}; lhz direct-signatures={len(selected_ids)}; "
                f"unique final names={len(set(selected_names))}"
            )
            for name in sorted(set(selected_names))[:50]:
                print(f"[*] {name}")
        return

    stems = discover_assets_db_stems(args.assets_dir)
    if not stems:
        raise SystemExit(f"No db_*.nmp with matching .map under {args.assets_dir}")

    databases: Dict[str, Dict[str, List[Dict[str, object]]]] = {}
    counts: Dict[str, int] = {}
    for stem in stems:
        nmp = args.assets_dir / f"{stem}.nmp"
        try:
            map_path = _pick_db_map(args.assets_dir, stem)
            rules = load_rules_from_db(nmp, map_path, stem, max_rules=max_rules)
        except (FileNotFoundError, ValueError) as e:
            print(f"[!] skip {stem}: {e}", file=sys.stderr)
            continue
        databases[stem] = rules
        counts[stem] = len(rules)

    out_obj: Dict[str, object] = {
        "source": "avast_py_simulate.engine",
        "databases": databases,
        "database_stems": list(databases.keys()),
        "virus_counts_by_stem": counts,
    }
    if "db_dex" in databases:
        out_obj["dex"] = databases["db_dex"]
        out_obj["dex_virus_count"] = counts["db_dex"]
    if "db_elfa" in databases:
        out_obj["elfa"] = databases["db_elfa"]
        out_obj["elfa_virus_count"] = counts["db_elfa"]

    args.out.write_text(json.dumps(out_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    total = sum(counts.values())
    print(f"[+] Wrote {args.out} (databases={len(databases)}, total virus keys={total})")
    for stem, n in sorted(counts.items()):
        print(f"    {stem}: {n} virus names (keys)")

    # Quick sanity sample (first non-empty db)
    for stem, rules in sorted(databases.items()):
        if rules:
            k = next(iter(rules.keys()))
            print(f"[*] {stem} sample virus: {k}")
            print(f"    rules_for_virus: {len(rules[k])}, first_rule: {rules[k][0]}")
            break


if __name__ == "__main__":
    main()

