# Threat model

## Protected against

1. **Stolen vault file** — Argon2id + AES-256-GCM; KDF params bounds-checked
   before derivation so forged headers cannot exhaust memory.
2. **Copied backup/snapshot** — same encryption, independently verifiable.
3. **Offline attacker with vault data** — brute force is the only path, and
   Argon2id prices it.
4. **Vault tampering** — header (AAD), records (AAD), chunks (AAD), wraps
   (AAD) all fail closed; no partial plaintext.
5. **Vault corruption** — hash manifests + full-unlock verification detect it;
   restore from snapshot/backup recovers.
6. **Replay of an older vault** — generation counter + trusted `state.json`
   refuse stale files, but ONLY while that state file exists and is not
   itself attacker-writable (see limitation 5 below).
7. **Accidental deletion** — pre-restore snapshots; `remove` confirms.
8. **Ransomware-like modification of accessible storage** — detected
   (integrity/generation signals), recovery via verified snapshots and
   *offline* backups. Same-disk copies are history, not protection.
9. **Secret leakage through CLI output** — values never in list/search/audit;
   names are terminal-escaped.
10. **Secret leakage through child inheritance** — `run` injects only
    `--secret` names; password/recovery env vars are stripped.
11. **Malformed vault input** — JSON/header/KDF/payload caps, no panics,
    fail-closed errors.
12. **Malicious import files** — size caps, name validation, counted skips.

## Out of scope / fundamentally limited

1. Fully compromised OS; hostile root/admin process.
2. Keyloggers, debuggers attached while unlocked, memory inspection.
3. A child process intentionally given a secret (it can leak it — by design).
4. Physical coercion; compromised user account/hardware.
5. Attacker replacing **both** `vault.json` **and** `state.json` consistently:
   locally indistinguishable — this is exactly what offline backups defeat.
6. Forensic remnants of old ciphertext on disk (SSD/filesystem reality).
7. Swap/pagefile disclosure of unlocked plaintext (zeroization is
   best-effort, not a guarantee).

## Honest vocabulary

Use: "designed to protect sensitive data at rest", "tamper-evident
encrypted vault", "verified recovery", "ransomware-resilient backup
workflow" (only with offline copies). Never: "ransomware proof",
"unhackable", "100% secure", "military grade".
