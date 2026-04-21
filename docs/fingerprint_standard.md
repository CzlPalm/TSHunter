# TSHunter Canonical Fingerprint Standard

## Stopping rule
- Linear walk from function entry.
- Each instruction's bytes are accumulated before the stop test, so the stopping instruction is included in the fingerprint.
- `CALL` passes through.
- `JMP` stops immediately.
- Any other `J*` / `RET` / `RETN` / `RETF` stops iff length >= 32 bytes.
- `MAX_CAP = 256` bytes as a safety cap.

## Output format
- Uppercase hex
- Space-separated
- No trailing space
- Compatible with Frida byte matcher usage

## Authority
Source of truth: `ExtractKDFFingerprint.java`

## Implementation
Canonical implementation: `scripts/TLShunterAnalyzer.java` -> `getLengthUntilStop()`

