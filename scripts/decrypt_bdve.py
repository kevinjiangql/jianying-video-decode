#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BDVE (ByteDance Video Encryption) periodic-XOR MP4 decryptor.

Usage:
    python decrypt_bdve.py <input.mp4> <output.mp4>

Strips the 68-byte BDVE footer, derives (step, length, key) from the footer
SHA-256 digest, and writes the recovered plaintext MP4.

v1.1.0 changes (verified on four real Jianying 11.5.3 files):
  - moov is located in the raw payload first and in a full-XOR copy as
    fallback (it may lie inside an XOR window).
  - Encryption state of each sample is primarily decided by its 4-byte AVCC
    NAL length prefix; H.264 NAL scoring is a fallback only.
  - XOR windows are applied via a 256-byte translate table for speed.
  - co64 chunk offsets are supported.
"""
from __future__ import annotations
import hashlib
import sys
from pathlib import Path

__version__ = "1.1.0"
# Verified against 剪映专业版 (Jianying Pro) 11.5.3 draft-cache MP4s.
SUPPORTED_JIANYING = "11.5.3"

MAX_STEP = 5_000_000
MIN_ANCHORS = 10  # minimum anchors per side before falling back to NAL scoring


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


def u64(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "big")


def iter_boxes(data: bytes, start: int, end: int):
    c = start
    while c + 8 <= end:
        sz = u32(data, c)
        t = data[c + 4:c + 8]
        hs = 8
        if sz == 1:
            sz = u64(data, c + 8)
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


def locate_moov(buf: bytes, end: int):
    """Return (offset, size) of a validated moov box in buf, or None.

    A raw 'moov' byte match is not enough (it can occur in ciphertext); the
    declared size must be sane and the body must contain trak/stsz/stco.
    """
    search = 0
    while True:
        idx = buf.find(b"moov", search, end)
        if idx < 4:
            return None
        sz = u32(buf, idx - 4)
        start = idx - 4
        if 8 < sz <= end - start:
            body = buf[idx + 4:start + sz]
            if b"trak" in body and b"stsz" in body and (b"stco" in body or b"co64" in body):
                return start, sz
        search = idx + 1


def parse_video_samples(buf: bytes, moov_box):
    """Reconstruct (pos, size) of every video sample from the given moov view."""
    moov_off, moov_sz = moov_box
    for c, sz, t, hs in iter_boxes(buf, moov_off + 8, moov_off + moov_sz):
        if t != b"trak":
            continue
        h = find_path(buf, (c, sz, hs), (b"mdia", b"hdlr"))
        if h is None:
            continue
        ho = h[0] + h[2]
        if buf[ho + 8:ho + 12] != b"vide":
            continue
        stbl = find_path(buf, (c, sz, hs), (b"mdia", b"minf", b"stbl"))
        if stbl is None:
            continue

        so, ssz, sh = find_child(buf, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stsz")
        off = so + sh
        us = u32(buf, off + 4)
        cnt = u32(buf, off + 8)
        sizes = [us] * cnt if us else [u32(buf, off + 12 + i * 4) for i in range(cnt)]

        coff_box = find_child(buf, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stco")
        if coff_box is None:
            coff_box = find_child(buf, stbl[0] + stbl[2], stbl[0] + stbl[1], b"co64")
        co, csz, ch = coff_box
        off = co + ch
        ec = u32(buf, off + 4)
        wide = coff_box[2] == 8 and buf[co + 4:co + 8] == b"co64"
        if wide:
            chunks = [u64(buf, off + 8 + i * 8) for i in range(ec)]
        else:
            chunks = [u32(buf, off + 8 + i * 4) for i in range(ec)]

        sco, scsz, sch = find_child(buf, stbl[0] + stbl[2], stbl[0] + stbl[1], b"stsc")
        off = sco + sch
        nent = u32(buf, off + 4)
        entries = [
            (u32(buf, off + 8 + i * 12),
             u32(buf, off + 8 + i * 12 + 4),
             u32(buf, off + 8 + i * 12 + 8))
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
    """Score AVCC sample bytes by walking NAL length prefixes (fallback oracle)."""
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


def build_observations(payload: bytes, key: int, footer_start: int):
    """Return (enc_positions, plain_positions) from markers + sample oracles."""
    obs_enc = {0, 4, 32}
    obs_plain = set()

    # Marker anchors
    for marker in (b"ftyp", b"mdat", b"moov"):
        em = bytes(x ^ key for x in marker)
        p = payload.find(em, 0, footer_start)
        while p >= 0:
            obs_enc.add(p)
            p = payload.find(em, p + 1, footer_start)
        p = payload.find(marker, 0, footer_start)
        while p >= 0:
            # A marker sitting inside the validated moov body is structural,
            # not ciphertext; plaintext markers elsewhere are real anchors.
            obs_plain.add(p)
            p = payload.find(marker, p + 1, footer_start)

    # Locate moov (raw first, then full-XOR fallback)
    table = bytes(b ^ key for b in range(256))
    moov_box = locate_moov(payload, footer_start)
    moov_buf = payload
    if moov_box is None:
        xored_all = payload.translate(table)
        moov_box = locate_moov(xored_all, footer_start)
        moov_buf = xored_all
        if moov_box is None:
            raise RuntimeError("moov box not found in either raw or XORed payload")
    moov_state = "plaintext" if moov_buf is payload else "encrypted"
    print(f"moov: offset={moov_box[0]} size={moov_box[1]} ({moov_state})", file=sys.stderr)

    samples = parse_video_samples(moov_buf, moov_box)
    print(f"video samples: {len(samples)}", file=sys.stderr)

    key_mask = key * 0x01010101
    ambiguous = []
    for pos, size in samples:
        if pos < 0 or size <= 4 or pos + 4 > footer_start:
            continue
        raw_val = u32(payload, pos)
        xor_val = raw_val ^ key_mask
        raw_ok = 0 < raw_val < size
        xor_ok = 0 < xor_val < size
        if xor_ok and not raw_ok:
            obs_enc.add(pos)
        elif raw_ok and not xor_ok:
            obs_plain.add(pos)
        else:
            ambiguous.append((pos, size))

    # Fallback oracle for ambiguous samples if anchors are scarce
    if min(len(obs_enc), len(obs_plain)) < MIN_ANCHORS and ambiguous:
        print("length-prefix anchors scarce; applying NAL scoring fallback", file=sys.stderr)
        for pos, size in ambiguous:
            if pos + size > footer_start:
                continue
            raw = payload[pos:pos + size]
            xo = raw.translate(table)
            if score_h264(xo) > score_h264(raw):
                obs_enc.add(pos)
            elif score_h264(raw) > score_h264(xo):
                obs_plain.add(pos)

    enc_list = sorted(obs_enc)
    plain_list = sorted(obs_plain)
    print(f"observations: encrypted={len(enc_list)} plaintext={len(plain_list)}", file=sys.stderr)
    return enc_list, plain_list


def digest_match(step: int, length: int, key: int, target: bytes) -> bool:
    h = hashlib.sha256(step.to_bytes(4, "big") + length.to_bytes(4, "big") + bytes([key]))
    return h.digest() == target


def discover_params(key: int, enc_obs, plain_obs, target: bytes):
    a = max(enc_obs)
    b = max(plain_obs)
    ranges = list(enum_anchor(a, b, MAX_STEP))
    ranges = intersect(ranges, list(enum_anchor(40, b, MAX_STEP)))

    # Fast path: anchor-quotient ranges
    for lo, hi in ranges:
        for step in range(lo, hi + 1):
            f = feasible(step, enc_obs, plain_obs)
            if f is None:
                continue
            low, high = f
            for length in range(low, high + 1):
                if digest_match(step, length, key, target):
                    return step, length

    # Fallback: plain linear scan over all steps
    print("anchor search missed; linear scanning steps", file=sys.stderr)
    for step in range(1, MAX_STEP + 1):
        f = feasible(step, enc_obs, plain_obs)
        if f is None:
            continue
        low, high = f
        for length in range(low, high + 1):
            if digest_match(step, length, key, target):
                return step, length
    raise RuntimeError("could not derive BDVE parameters from footer digest")


def recover(input_path: Path, output_path: Path):
    data = input_path.read_bytes()
    if len(data) < 68:
        raise RuntimeError("file too small to contain BDVE footer")

    footer_size = u32(data, len(data) - 4)
    if footer_size != 0x44 or data[-footer_size + 4:-footer_size + 8] != b"bdve":
        raise RuntimeError("BDVE footer signature not found")

    footer_start = len(data) - footer_size
    crpt_off = footer_start + 8
    assert data[crpt_off + 4:crpt_off + 8] == b"crpt"
    cryptor_type = u32(data, crpt_off + 8)
    if cryptor_type != 1:
        raise RuntimeError(f"unsupported BDVE cryptor type: {cryptor_type}")
    target = data[crpt_off + 16:crpt_off + 48]

    key = data[0]
    payload = data[:footer_start]
    print(f"BDVE footer: key=0x{key:02X} digest={target.hex()}", file=sys.stderr)

    enc_obs, plain_obs = build_observations(payload, key, footer_start)
    if not enc_obs or not plain_obs:
        raise RuntimeError("not enough observations to constrain step/length")

    step, length = discover_params(key, enc_obs, plain_obs, target)
    print(f"BDVE params: step={step}, length={length}, key=0x{key:02X}", file=sys.stderr)

    table = bytes(b ^ key for b in range(256))
    out = bytearray(payload)
    n = len(out)
    for i in range(0, n, step):
        e = min(i + length, n)
        out[i:e] = payload[i:e].translate(table)

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
