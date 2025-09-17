#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Split a Fujifilm multi-image RAF into separate single-image RAFs.

v3 Strategy (robust):
A) Whole-file TIFF scan (preferred):
   - Find all TIFF headers (`II*\x00` or `MM\x00*`) in the entire file.
   - Exclude any header that lies inside the JPEG preview (EXIF TIFF).
   - If 2+ headers remain, split the file into frames at those boundaries.
B) Fallback (single-TIFF, multi-IFD/SubIFD layout inside CFA region):
   - Parse IFD chain + SubIFDs (tag 330). For each candidate IFD,
     duplicate the entire TIFF block and rewrite the TIFF header's
     IFD0 pointer (offset 4) to point at that IFD. Pack into a new RAF.
     
All outputs preserve the original JPEG preview and meta container;
header offsets/lengths are recomputed in big-endian.
"""

import sys
import struct
from pathlib import Path
from typing import List, Tuple

HEADER_SIZE = 0x78

def be_u16(b, off): return struct.unpack_from(">H", b, off)[0]
def be_u32(b, off): return struct.unpack_from(">I", b, off)[0]
def le_u16(b, off): return struct.unpack_from("<H", b, off)[0]
def le_u32(b, off): return struct.unpack_from("<I", b, off)[0]

def read_header(buf: bytes):
    if len(buf) < HEADER_SIZE:
        raise ValueError("File too small to be a RAF.")
    magic = buf[0x00:0x10]
    if magic != b"FUJIFILMCCD-RAW ":
        raise ValueError("Not a RAF (magic mismatch).")

    hdr = {}
    hdr["magic"] = magic
    hdr["version"] = buf[0x10:0x14]
    hdr["cam_code"] = buf[0x14:0x1C]
    hdr["cam_str"] = buf[0x1C:0x3C].split(b"\x00",1)[0]
    hdr["dir_ver"] = be_u32(buf, 0x3C)        # directory version (opaque)
    hdr["unknown20"] = buf[0x40:0x54]         # keep verbatim

    # Big-endian offset/length pairs:
    hdr["jpeg_off"] = be_u32(buf, 0x54)
    hdr["jpeg_len"] = be_u32(buf, 0x58)
    hdr["meta_off"] = be_u32(buf, 0x5C)
    hdr["meta_len"] = be_u32(buf, 0x60)
    hdr["cfa_off"]  = be_u32(buf, 0x64)
    hdr["cfa_len"]  = be_u32(buf, 0x68)

    hdr["unknown12"] = buf[0x6C:0x78]
    hdr["raw_header"] = buf[:HEADER_SIZE]
    return hdr

def align(n: int, a: int = 16) -> int:
    return (n + (a - 1)) // a * a

def slice_or_none(buf: bytes, off: int, ln: int) -> bytes:
    if off == 0 or ln == 0: return None
    end = off + ln
    if end > len(buf): raise ValueError("Block extends past EOF.")
    return buf[off:end]

def tiff_hits_fullfile(buf: bytes) -> List[int]:
    """Return all absolute offsets of TIFF headers (II*\\x00 or MM\\x00*)."""
    hits = []
    i = 0
    while True:
        pos_ii = buf.find(b"II*\x00", i)
        pos_mm = buf.find(b"MM\x00*", i)
        cand = [p for p in (pos_ii, pos_mm) if p != -1]
        if not cand:
            break
        p = min(cand)
        hits.append(p)
        i = p + 4
    return hits

def tiff_blocks_from_hits(buf: bytes, hits: List[int], exclude_ranges: List[Tuple[int,int]]):
    """Build non-overlapping blocks [start, next_hit) from hits, excluding any hit inside exclude ranges."""
    def in_exclude(h):
        for a,b in exclude_ranges:
            if a <= h < b:
                return True
        return False

    fhits = [h for h in hits if not in_exclude(h)]
    fhits.sort()
    if not fhits:
        return []

    blocks = []
    for idx, s in enumerate(fhits):
        e = fhits[idx+1] if idx+1 < len(fhits) else len(buf)
        blocks.append((s, e))
    return blocks

def pack_raf(orig_bytes: bytes, hdr: dict, jpeg: bytes, meta: bytes, tiff_bytes: bytes, ifd0_rel: int = None) -> bytes:
    """Assemble a new RAF with header+JPEG+META+TIFF. If ifd0_rel is set, rewrite TIFF IFD0 pointer to that value."""
    out = bytearray(HEADER_SIZE)
    cursor = HEADER_SIZE

    def put_block(block: bytes):
        nonlocal cursor, out
        off = align(cursor, 16)
        if off > len(out):
            out.extend(b"\x00" * (off - len(out)))
        out.extend(block)
        cursor = off + len(block)
        return off, len(block)

    jpeg_off = jpeg_len = 0
    if jpeg:
        jpeg_off, jpeg_len = put_block(jpeg)
    meta_off = meta_len = 0
    if meta:
        meta_off, meta_len = put_block(meta)

    tiff_copy = bytearray(tiff_bytes)
    if ifd0_rel is not None and tiff_copy[:2] in (b"II", b"MM"):
        if tiff_copy[:2] == b"II":
            struct.pack_into("<I", tiff_copy, 4, ifd0_rel)
        else:
            struct.pack_into(">I", tiff_copy, 4, ifd0_rel)

    tiff_off, tiff_len = put_block(tiff_copy)

    # Start from original header to preserve unknown fields, then update offsets/lengths (BE)
    out[:HEADER_SIZE] = orig_bytes[:HEADER_SIZE]
    struct.pack_into(">I", out, 0x54, jpeg_off)
    struct.pack_into(">I", out, 0x58, jpeg_len)
    struct.pack_into(">I", out, 0x5C, meta_off)
    struct.pack_into(">I", out, 0x60, meta_len)
    struct.pack_into(">I", out, 0x64, tiff_off)
    struct.pack_into(">I", out, 0x68, tiff_len)

    return bytes(out)

def parse_ifd_offsets_in_tiff(tiff_bytes: bytes, tiff_abs_off: int) -> List[int]:
    """Return absolute (file) offsets of IFDs (main chain + SubIFDs 330)."""
    if len(tiff_bytes) < 8: return []
    endian = tiff_bytes[:2]
    if endian not in (b"II", b"MM"): return []
    is_le = (endian == b"II")
    U16 = (lambda off: le_u16(tiff_bytes, off)) if is_le else (lambda off: be_u16(tiff_bytes, off))
    U32 = (lambda off: le_u32(tiff_bytes, off)) if is_le else (lambda off: be_u32(tiff_bytes, off))
    if U16(2) != 42: return []

    visited = set()
    ifd_abs = []

    def add_ifd(rel_off):
        if rel_off == 0: return
        abs_off = tiff_abs_off + rel_off
        if abs_off not in visited and 0 <= rel_off < len(tiff_bytes):
            visited.add(abs_off)
            ifd_abs.append(abs_off)

    rel = U32(4)  # IFD0
    while rel:
        abs_off = tiff_abs_off + rel
        if abs_off in visited: break
        visited.add(abs_off)
        ifd_abs.append(abs_off)

        cnt = U16(rel)
        next_ptr_off = rel + 2 + cnt*12
        # SubIFDs (330)
        for i in range(cnt):
            e = rel + 2 + i*12
            tag = U16(e)
            typ = U16(e+2)  # not used
            cntv = U32(e+4)
            if tag == 330:
                if cntv == 1:
                    sub_rel = U32(e+8)
                    add_ifd(sub_rel)
                elif cntv > 1:
                    arr_rel = U32(e+8)
                    for k in range(cntv):
                        off = arr_rel + 4*k
                        if off + 4 <= len(tiff_bytes):
                            sub_rel = U32(off)
                            add_ifd(sub_rel)
        rel = U32(next_ptr_off)

    return ifd_abs

def split_hdr_raf(input_path: str) -> list:
    p = Path(input_path)
    buf = p.read_bytes()
    size = len(buf)
    hdr = read_header(buf)

    # Gather ranges to exclude from whole-file TIFF header detection (JPEG EXIF)
    exclude = []
    if hdr["jpeg_off"] and hdr["jpeg_len"]:
        exclude.append((hdr["jpeg_off"], hdr["jpeg_off"] + hdr["jpeg_len"]))

    hits = tiff_hits_fullfile(buf)
    blocks = tiff_blocks_from_hits(buf, hits, exclude_ranges=exclude)

    # If we found multiple full-file TIFFs, split on those
    if len(blocks) >= 2:
        jpeg = slice_or_none(buf, hdr["jpeg_off"], hdr["jpeg_len"])
        meta = slice_or_none(buf, hdr["meta_off"], hdr["meta_len"])
        outs = []
        stem = str(p.with_suffix(""))
        for i, (s,e) in enumerate(blocks, 1):
            tiff_bytes = buf[s:e]
            raf_bytes = pack_raf(buf, hdr, jpeg, meta, tiff_bytes)
            outp = f"{stem}_part{i}.RAF"
            Path(outp).write_bytes(raf_bytes)
            outs.append(outp)
        return outs

    # Fallback: look for multi-IFD TIFF inside CFA region
    cfa = slice_or_none(buf, hdr["cfa_off"], hdr["cfa_len"])
    if not cfa:
        raise ValueError("CFA/TIFF region empty; nothing to split.")

    # Find TIFF header inside CFA
    rel_ii = cfa.find(b"II*\x00")
    rel_mm = cfa.find(b"MM\x00*")
    if rel_ii == -1 and rel_mm == -1:
        raise ValueError("No TIFF header found in CFA region.")
    rel = rel_ii if rel_ii != -1 and (rel_mm == -1 or rel_ii < rel_mm) else rel_mm
    tiff_abs = hdr["cfa_off"] + rel
    tiff_bytes = buf[tiff_abs: hdr["cfa_off"] + hdr["cfa_len"]]

    ifd_abs = parse_ifd_offsets_in_tiff(tiff_bytes, tiff_abs)
    if len(ifd_abs) <= 1:
        raise ValueError("Only one TIFF/IFD found; file may not be multi-image.")
    ifd_rel = [a - tiff_abs for a in ifd_abs]

    jpeg = slice_or_none(buf, hdr["jpeg_off"], hdr["jpeg_len"])
    meta = slice_or_none(buf, hdr["meta_off"], hdr["meta_len"])
    outs = []
    stem = str(p.with_suffix(""))
    for i, rel_off in enumerate(ifd_rel, 1):
        raf_bytes = pack_raf(buf, hdr, jpeg, meta, tiff_bytes, ifd0_rel=rel_off)
        outp = f"{stem}_part{i}.RAF"
        Path(outp).write_bytes(raf_bytes)
        outs.append(outp)
    return outs

def main(argv=None):
    argv = argv or sys.argv
    if len(argv) != 2:
        print("Usage: python split_hdr_raf_v3.py <input.RAF>")
        return 2
    outs = split_hdr_raf(argv[1])
    for o in outs:
        print(o)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
