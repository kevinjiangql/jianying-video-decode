---
name: jianying-video-decode
version: 1.0.0
description: Decrypt Jianying/CapCut draft-cache MP4 files obfuscated with the BDVE periodic-XOR scheme. Use when the user asks to recover or decode a *_video.mp4 under a Jianying/CapCut Resources/combination or cached-media folder that ffprobe cannot parse. Do not use for already-plaintext MP4s (including most .alpha.mp4 sidecars) or for non-BDVE encryption.
---

# Jianying BDVE Video Decode

Recovers a playable MP4 from a ByteDance Video Encryption (BDVE) cached draft file by
stripping its 68-byte trailer and reversing a single-byte periodic XOR.

## Version & Compatibility

- **Skill version:** 1.0.0
- **Tested against:** 剪映专业版 (Jianying Pro) **11.5.3** draft-cache MP4s under
  `Resources/combination/` and `Resources/cached-media/`.
- The BDVE periodic-XOR scheme (68-byte footer, `cryptor_type=1`,
  `SHA256(step‖length‖key)` digest) was verified on files produced by this version.
  Future Jianying versions may change the footer layout or cryptor type; if
  `parse_bdve_footer` fails or the digest never matches, re-inspect the last 68+
  bytes of a fresh sample before adjusting the algorithm.

## Quick decision

1. Run `ffprobe` on the candidate. If it opens cleanly, the file is already plaintext — copy it as-is (this is common for `*.alpha.mp4` sidecars).
2. If the file starts with bytes that are not `00 00 00 XX 66 74 79 70` (ftyp), it is BDVE encrypted. Proceed.

## Footer format (last 68 bytes)

```
[ u32 size=0x44 ] 'bdve'
[ u32 size=0x30 ] 'crpt' [ u32 cryptor_type ] [ u32 version ] [ 32B SHA256 ]
[ u32 size=0x0c ] 'size' [ u32 size=0x44 ]
```

- `cryptor_type` is expected to be `1` (periodic XOR). Anything else is unsupported by this procedure.
- `key` is the **first byte** of the file (XOR of the ftyp size high byte `0x00` with the cipher byte — typically `0x25`).
- The 32-byte digest is **the full SHA256** of `BE32(step) || BE32(length) || u8(key)`. It is NOT split into salt+digest. Do not brute-force salt combinations.

## Decryption rule

Strip the 68-byte footer, then for each `step`-aligned block from offset 0, XOR the first `length` bytes with `key`; the rest of the block stays as-is:

```
for i in range(0, n, step):
    end = min(i + length, n)
    for j in range(i, end):
        out[j] ^= key
```

## Parameter discovery (deterministic, do not guess)

The default profiles in public scripts (`1022554/311610`, `102303/89230`) often do NOT match real files. Always derive `(step, length)` from the footer digest:

1. Parse the plaintext `moov` (it lives at the end of the file, before the footer, and is never encrypted because it starts past all XOR windows) to get the video `stsz`, `stsc`, `stco` tables and reconstruct every sample's `(pos, size)`.
2. Build observations `(pos, is_encrypted)`:
   - `(0, True), (4, True), (32, True)` — the ftyp header bytes are always encrypted.
   - Find encrypted and plaintext occurrences of `ftyp`, `mdat`, `moov` markers within `[0, footer_start)`: encrypted = `marker ^ key`, plaintext = `marker`.
   - For each of the first ~260 video samples, score its raw bytes vs its XORed bytes by H.264 NAL validity (NAL types 1/5/6/7/8/9 are good). Mark `sample.pos` encrypted iff `xor_score >= raw_score`.
3. For a candidate `step`, the model is: byte at file offset `p` is encrypted iff `p % step < length`. Each observation yields a constraint:
   - encrypted `p` → `length > p % step`, i.e. `low = max(low, (p % step) + 1)`
   - plaintext `p` → `length <= p % step`, i.e. `high = min(high, p % step)`
   `length` is feasible only while `1 <= low <= high <= step`.
4. Enumerate `step` in `[1, 5_000_000]` (use constant-quotient blocks over the strongest encrypted/plaintext anchor pair to skip most steps), then for each feasible `(step, length)` test:
   `sha256(step.to_bytes(4,'big') + length.to_bytes(4,'big') + bytes([key])) == footer_digest`.
   The first match is the unique answer.

Reference implementation: see `scripts/decrypt_bdve.py` in this skill.

## Verification (mandatory)

`ffmpeg -f null` error counts are **not** a reliable oracle — a near-miss `length` (off by a few hundred bytes) decodes with zero hard errors but renders horizontal stripes in the lower portion of frames. Always:

1. `ffmpeg -v warning -i out.mp4 -f null NUL` — expect no errors.
2. `ffprobe -count_packets -show_entries stream=codec_name,width,height,nb_read_packets out.mp4` — packet counts must match the `stsz`/`stsc` tables.
3. Render the first and last frames as PNG (`-frames:v 1 -update 1 frame.png`) and visually confirm there are no decoding stripes. A correct decrypt shows a full clean frame; a wrong `length` shows a sharp horizontal boundary with garbage below.

## Failure modes

- digest mismatch for all feasible `(step,length)` → re-check the footer byte layout; the 32-byte digest starts at `footer_start + 8 (bdve header) + 8 (crpt header) + 4 (type) + 4 (version)`.
- ffmpeg reports 0 errors but frame PNG is striped → `length` is wrong; the digest match must have been on a wrong `step`. Re-verify the observation set, especially plaintext markers that may have been misclassified.
- `moov` not found → the file is not a standard BDVE MP4; this procedure does not apply.
