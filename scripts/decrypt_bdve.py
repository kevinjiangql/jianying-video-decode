#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BDVE (ByteDance Video Encryption) periodic-XOR MP4 decryptor.

Usage:
    python decrypt_bdve.py <input.mp4> <output.mp4>

Strips the 68-byte BDVE footer, derives (step, length, key) from the footer
SHA-256 digest, and writes the recovered plaintext MP4.
"""
from __future__ import annotations
import hashlib
import os
import struct
import sys
from pathlib import Path

__version__ = "1.0.0"
# Verified against 剪映专业版 (Jianying Pro) 11.5.3 draft-cache MP4s.
SUPPORTED_JIANYING = "11.5.3"

MAX_STEP = 5_000_000


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


def iter_boxes(data: bytes, start: int, end: int):
    c = start
    while c + 8 <= end:
        sz = u32(data, c)
        t = data[c + 4:c + 8]
        hs = 8
        if sz == 1:
            sz = int.from_bytes(data[c + 8:c + 16], "big")
            hs = 16
        elif sz == 0:
            sz = end - c
        if sz < hs or c + sz > end:
            return
        yield c, sz, t, hs
        c += sz


def find_child(data, start, end, want):
    for c, sz, t, hs in iter_boxes(data, start, end):
        if t == want:
            return c, sz, hs
    return None


def find_path(data, box, path):
    c, sz, hs = box
    for name in path:
        r = find_child(data, c + hs, c + sz, name)
        if r is None:
            return None
        c, sz, hs = r
    return c, sz, hs


def parse_video_samples(data: bytes, footer_start: int):
    """Reconstruct (pos, size) of every video sample from the plaintext moov."""
    moov_pos = data.find(b"moov", 0, footer_start)
    if moov_pos < 0:
        raise RuntimeError("moov box not found")
    moov = (moov_pos - 4, u32(data, moov_pos - 4), 8)
    for c, sz, t, hs in iter_boxes(data, moov[0] + moov[2], moov[0] + moov[1]):
        if t != b"trak":
            continue
        h = find_path(data, (c, sz, hs), (b"mdia", b"hdlr"))
        if h is None:
            continue
        ho = h[0] + h[2]
        if data[ho + 8:ho + 12] != b"vide":
            continue
        stbl = find_path(data, (c, sz, hs), (b"mdia", b"minf", b"stbl"))
        so, ssz, sh = find_child(data, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stsz")
        co, csz, ch = find_child(data, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stco")
        sco, scsz, sch = find_child(data, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stsc")
        off = so + sh
        us = u32(data, off + 4)
        cnt = u32(data, off + 8)
        sizes = [us] * cnt if us else [u32(data, off + 12 + i * 4) for i in range(cnt)]
        off = co + ch
        ec = u32(data, off + 4)
        chunks = [u32(data, off + 8 + i * 4) for i in range(ec)]
        off = sco + sch
        nent = u32(data, off + 4)
        entries = [
            (u32(data, off + 8 + i * 12),
             u32(data, off + 8 + i * 12 + 4),
             u32(data, off + 8 + i * 12 + 8))
            for i in range(nent)
        ]
        samples = []
        si = 0
        ei = 0
        for cn, coff in enumerate(chunks, 1):
            while ei + 1 < len(entries) and entries[ei + 1][0] <= cn:
                ei += 1
            spc = entries[ei][1]
            cur = coff
            for _ in range(spc):
                if si >= len(sizes):
                    break
                samples.append((cur, sizes[si]))
                cur += sizes[si]
                si += 1
        return samples
    raise RuntimeError("no video trak found")


def score_h264(sample: bytes) -> int:
    off = 0
    score = 0
    nal_count = 0
    lim = len(sample)
    while off + 5 <= lim and nal_count < 10:
        ns = int.from_bytes(sample[off:off + 4], "big")
        if ns <= 0 or ns > lim - off - 4:
            score -= 5
            break
        nt = sample[off + 4] & 0x1F
        if nt in {1, 5, 6, 7, 8, 9}:
            score += 4
        elif 1 <= nt <= 23:
            score += 1
        else:
            score -= 3
        off += 4 + ns
        nal_count += 1
        if off == lim:
            score += 6
            break
    if nal_count == 0:
        score -= 10
    return score


def feasible(step: int, enc_obs, plain_obs):
    low = 1
    high = step
    for p in enc_obs:
        r = p % step
        if r + 1 > low:
            low = r + 1
    for p in plain_obs:
        r = p % step
        if r < high:
            high = r
    return (low, high) if low <= high else None


def enum_anchor(a: int, b: int, smax: int):
    """Yield (lo, hi) step ranges where a%step < b%step (enc anchor a, plain anchor b)."""
    s = 1
    while s <= smax:
        qa = a // s
        qb = b // s
        nb = b // qb if qb else smax
        na = a // qa if qa else smax
        end = min(nb, na, smax)
        if qa == qb:
            if 0 < b - a:
                yield s, end
        else:
            c = qb - qa
            if c > 0:
                lim = (b - a - 1) // c
                e2 = min(end, lim)
                if s <= e2:
                    yield s, e2
            else:
                yield s, end
        s = end + 1


def intersect(r1, r2):
    i = j = 0
    out = []
    while i < len(r1) and j < len(r2):
        lo = max(r1[i][0], r2[j][0])
        hi = min(r1[i][1], r2[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if r1[i][1] < r2[j][1]:
            i += 1
        else:
            j += 1
    return out


def discover_params(data: bytes, key: int, footer_start: int, target: bytes):
    obs = [(0, True), (4, True), (32, True)]
    xb = lambda b: bytes(x ^ key for x in b)
    for marker in (b"ftyp", b"mdat", b"moov"):
        em = xb(marker)
        ep = data.find(em, 0, footer_start)
        rp = data.find(marker, 0, footer_start)
        if ep >= 0:
            obs.append((ep, True))
        if rp >= 0:
            obs.append((rp, False))

    try:
        samples = parse_video_samples(data, footer_start)
    except RuntimeError:
        samples = []
    for pos, size in samples[:260]:
        if pos < 0 or size <= 0 or pos + size > footer_start:
            continue
        raw = data[pos:pos + size]
        xo = xb(raw)
        obs.append((pos, score_h264(xo) >= score_h264(raw)))

    enc_obs = [p for p, e in obs if e]
    plain_obs = [p for p, e in obs if not e]
    if not enc_obs or not plain_obs:
        raise RuntimeError("not enough observations to constrain step/length")

    a = max(enc_obs)
    b = max(plain_obs)
    ranges = list(enum_anchor(a, b, MAX_STEP))
    ranges = intersect(ranges, list(enum_anchor(40, b, MAX_STEP)))

    for lo, hi in ranges:
        for step in range(lo, hi + 1):
            f = feasible(step, enc_obs, plain_obs)
            if not f:
                continue
            low, high = f
            sb = step.to_bytes(4, "big")
            for length in range(low, high + 1):
                if hashlib.sha256(sb + length.to_bytes(4, "big") + bytes([key])).digest() == target:
                    return step, length
    raise RuntimeError("could not derive BDVE parameters from footer digest")


def recover(input_path: Path, output_path: Path):
    data = input_path.read_bytes()
    if len(data) < 68:
        raise RuntimeError("file too small to contain BDVE footer")

    footer_size = int.from_bytes(data[-4:], "big")
    if footer_size != 0x44 or data[-footer_size + 4:-footer_size + 8] != b"bdve":
        raise RuntimeError("BDVE footer signature not found")

    footer_start = len(data) - footer_size
    crpt_off = footer_start + 8
    crpt_size = int.from_bytes(data[crpt_off:crpt_off + 4], "big")
    assert data[crpt_off + 4:crpt_off + 8] == b"crpt"
    cryptor_type = int.from_bytes(data[crpt_off + 8:crpt_off + 12], "big")
    if cryptor_type != 1:
        raise RuntimeError(f"unsupported BDVE cryptor type: {cryptor_type}")
    target = data[crpt_off + 16:crpt_off + 48]

    key = data[0]
    step, length = discover_params(data, key, footer_start, target)
    print(f"BDVE params: step={step}, length={length}, key=0x{key:02X}", file=sys.stderr)

    out = bytearray(data[:footer_start])
    n = len(out)
    for i in range(0, n, step):
        e = min(i + length, n)
        for j in range(i, e):
            out[j] ^= key

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(out))
    print(f"wrote {output_path} ({len(out)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ("--version", "-V"):
        print(f"decrypt_bdve {__version__} (tested on 剪映专业版 {SUPPORTED_JIANYING})")
        sys.exit(0)
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input.mp4> <output.mp4>", file=sys.stderr)
        print(f"       {sys.argv[0]} --version", file=sys.stderr)
        sys.exit(1)
    recover(Path(sys.argv[1]), Path(sys.argv[2]))
