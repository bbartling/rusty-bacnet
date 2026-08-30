# Fork tip — MS/TP live interop

**Upstream PR:** https://github.com/jscott3201/rusty-bacnet/pull/467  
**Branch for review:** `pr/mstp-clause9-interop` (MS/TP only; rebased on `jscott3201/dev`)  
**Default `main`:** same MS/TP commits + Windows retry-budget timeout flake fix (not in the upstream PR)

## Commits (MS/TP)
1. USB chunk gaps ≠ T_frame_abort (stream decoder)
2. Clause 9.6 header/data CRCs (`0x81` / `0x8408`)
3. Split frame tests (700 LOC gate)
4. Clause 9.5.6 DONE_WITH_TOKEN / PFM

## Limitations
- Not a Clause 9 conformance claim
- No extended frames (32/33), COBS, CRC-32K
- Lab Gates 5–6 (shared endpoint + soak) still open
- Host USB stale-partial timeout ≠ wire T_frame_abort
