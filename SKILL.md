---
name: jianying-video-decode
version: 1.1.0
description: Decrypt Jianying/CapCut draft-cache MP4 files obfuscated with the BDVE periodic-XOR scheme. Use when the user asks to recover or decode a *_video.mp4 under a Jianying/CapCut Resources/combination or cached-media folder that ffprobe cannot parse. Do not use for already-plaintext MP4s (including most .alpha.mp4 sidecars) or for non-BDVE encryption.
---

# Jianying BDVE Video Decode

Recovers a playable MP4 from a ByteDance Video Encryption (BDVE) cached draft file by
stripping its 68-byte trailer and reversing a single-byte periodic XOR.

## Version & Compatibility

- **Skill version:** 1.1.0
- **Tested against:** 剪映专业版 (Jianying Pro) **11.5.3** draft-cache MP4s under
  `Resources/combination/` and `Resources/cached-media/`.
- v1.1.0 verified end-to-end on four additional real files (keys `0x4D / 0x5F / 0xBE / 0x8B`,
  5–88 MB, 152–2577 video frames). Two findings from v1.0.0 were corrected:
  1. The `moov` box is **not always plaintext** — it can fall inside an XOR window.
  2. The most reliable encryption oracle is the **4-byte AVCC NAL length prefix**, not
     NAL-type scoring (scoring produced zero plaintext anchors on one real file).
- Future Jianying versions may change the footer layout or cryptor type; if the footer
  signature is missing or the digest never matches, re-inspect the last 68+ bytes of a
  fresh sample before adjusting the algorithm.

## Quick decision

1. Run `ffprobe` on the candidate. If it opens cleanly, the file is already plaintext — copy it as-is (this is common for `*.alpha.mp4` sidecars).
2. If the file starts with bytes that are not `00 00 00 XX 66 74 79 70` (ftyp), check the last 68 bytes for the `bdve`/`crpt` signature. If present, it is BDVE encrypted. Proceed.

## Footer format (last 68 bytes)

```
[ u32 size=0x44 ] 'bdve'
[ u32 size=0x30 ] 'crpt' [ u32 cryptor_type ] [ u32 version ] [ 32B SHA256 ]
[ u32 size=0x0c ] 'size' [ u32 size=0x44 ]
```

- `cryptor_type` is expected to be `1` (periodic XOR). Anything else is unsupported by this procedure.
- `key` is the **first byte** of the file (XOR of the ftyp size high byte `0x00` with the cipher byte). It is **not a fixed value** — observed keys include `0x25, 0x4D, 0x5F, 0xBE, 0x8B`. Always read it from the file.
- The 32-byte digest is **the full SHA256** of `BE32(step) || BE32(length) || u8(key)`. It is NOT split into salt+digest. Do not brute-force salt combinations.

## Decryption rule

Strip the 68-byte footer, then for each `step`-aligned block from offset 0, XOR the first `length` bytes with `key`; the rest of the block stays as-is:

```
for i in range(0, n, step):
    end = min(i + length, n)
    out[i:end] = payload[i:end].translate(XOR_TABLE)  # 256-byte table, NOT a Python per-byte loop
```

For files tens of MB large, a per-byte Python XOR loop is needlessly slow; a precomputed
256-byte translation table (`bytes(b ^ key for b in range(256))`) processes each window in
one `bytes.translate` call.

## Parameter discovery (deterministic, do not guess)

The default profiles in public scripts (`1022554/311610`, `102303/89230`) often do NOT match real files. Always derive `(step, length)` from the footer digest:

1. Locate and parse the `moov` box to get the video `stsz`, `stsc`, `stco` tables and reconstruct every sample's `(pos, size)`. **moov may be encrypted or plaintext depending on where it lands relative to the XOR windows:**
   - First search the raw payload for a `moov` marker whose declared size is sane and whose body contains `trak`/`stsz`/`stco`.
   - If none, XOR the whole payload with `key` (via `translate`) and search again. Parse whichever copy validates.
   - Select the video track by the `hdlr` handler type `vide` (files may carry a second AAC track).
2. Build observations `(pos, is_encrypted)`:
   - `(0, True), (4, True), (32, True)` — the ftyp header bytes are always encrypted.
   - Marker anchors: for `ftyp`, `mdat`, `moov`, record plaintext occurrences of the marker as `False`, and occurrences of `marker ^ key` as `True`, within `[0, footer_start)`.
   - **Primary oracle — AVCC NAL length prefix (preferred):** Jianying video samples are length-prefixed AVCC, so each sample starts with a 4-byte big-endian NAL size. Read `raw = u32(payload[pos:pos+4])` and `xored = raw ^ key*0x01010101`; the true value must satisfy `0 < val < sample_size`.
     - xored valid, raw invalid → encrypted
     - raw valid, xored invalid → plaintext
     - both valid or both invalid → ambiguous, skip this sample (do not force a verdict)
     On every file tested this alone produced 50–1900 anchors on each side.
   - **Fallback oracle — H.264 NAL scoring:** only if the length-prefix oracle yields too few anchors (< ~10 on either side), score raw vs XORed sample bytes by NAL validity (NAL types 1/5/6/7/8/9 are good; walk AVCC length prefixes and reward exact end-of-sample). Do not rely on scoring alone — on one real file every sample tied and was misclassified as encrypted, leaving zero plaintext anchors.
3. For a candidate `step`, the model is: byte at file offset `p` is encrypted iff `p % step < length`. Each observation yields a constraint:
   - encrypted `p` → `length > p % step`, i.e. `low = max(low, (p % step) + 1)`
   - plaintext `p` → `length <= p % step`, i.e. `high = min(high, p % step)`
   `length` is feasible only while `1 <= low <= high <= step`.
4. Enumerate `step` in `[1, 5_000_000]` (constant-quotient blocks over the strongest encrypted/plaintext anchor pair skip most steps; a plain scan of feasible steps also finishes in well under a minute once the oracle is good), then for each feasible `(step, length)` test:
   `sha256(step.to_bytes(4,'big') + length.to_bytes(4,'big') + bytes([key])) == footer_digest`.
   The first match is the unique answer.

### Observed parameter sets (regression reference)

| key (hex) | step | length | resolution | video frames | moov state |
|-----------|------|--------|------------|--------------|------------|
| 4D | 259978 | 182696 | 1660×1246 | 152 | encrypted |
| 5F | 663483 | 523369 | 720×1280 | 2426 | encrypted |
| BE | 691030 | 381312 | 720×1280 | 2426 | encrypted |
| 8B | 505727 | 285731 | 720×1280 | 2577 | plaintext |

Reference implementation: `scripts/decrypt_bdve.py` in this skill (CLI: `python decrypt_bdve.py <in.mp4> <out.mp4>`).

## Verification (mandatory)

`ffmpeg -f null` error counts are **not** a reliable oracle — a near-miss `length` (off by a few hundred bytes) decodes with zero hard errors but renders horizontal stripes in the lower portion of frames. Always:

1. `ffmpeg -v error -i out.mp4 -f null NUL` (Windows) / `/dev/null` (Unix) — expect no errors.
2. `ffprobe -show_entries stream=codec_name,width,height,nb_frames out.mp4` — stream metadata must look sane; packet counts should match the `stsz`/`stsc` tables.
3. Render the first and last frames as PNG (`-frames:v 1 frame.png`, and `-vf select=eq(n\,LAST)`) and visually confirm there are no decoding stripes. A correct decrypt shows a full clean frame; a wrong `length` shows a sharp horizontal boundary with garbage below.

## Failure modes

- digest mismatch for all feasible `(step,length)` → re-check the footer byte layout; the 32-byte digest starts at `footer_start + 8 (bdve header) + 8 (crpt header) + 4 (type) + 4 (version)`.
- "not enough observations" with zero plaintext anchors → the scoring oracle tied on every sample. Switch to the 4-byte NAL length-prefix oracle.
- `moov` found only after whole-payload XOR → that is normal (3 of 4 tested files). The stco offsets it contains still index the *plaintext* output layout, so reconstructed sample positions are the same either way.
- ffmpeg reports 0 errors but frame PNG is striped → `length` is wrong; re-verify the observation set, especially ambiguous samples that should have been skipped.
- no `bdve` footer and ffprobe also fails → the file is not a standard BDVE MP4; this procedure does not apply.
