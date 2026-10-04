# Recovery

Losing the master password used to mean losing the vault. With a recovery
wrap (v3 only), it doesn't have to.

## Create a recovery kit

```bash
sagitarrius recovery create
```

- Generates a random 256-bit code, stores only its Argon2id wrap in the
  vault header, prints the code **once**.
- Sagitarrius never writes the code anywhere. Write it on paper.
- Store it **offline and apart from the vault file**. Code + vault file =
  full password-reset capability.

```bash
sagitarrius recovery verify   # check a code, changes nothing
```

## Password lost? Reset it

```bash
sagitarrius recovery reset-password
```

Needs only the vault file + the code. Installs a fresh password wrap;
records are untouched, the old password dies, the code keeps working.

## Disaster drill (ransomware scenario)

1. Create 100 records, `snapshot create`, `backup create --to <usb>`.
2. Simulate destruction: delete or corrupt `vault.json`.
3. `backup restore <id>` (or snapshot restore) from the offline copy.
4. `snapshot verify` — full unlock proof.
5. `status` — generation current, recovery ready.

If the password was also lost, step 3.5 is `recovery reset-password`.

## What recovery is NOT

- Not "password recovery": nothing stores your password. The code unwraps
  the VMK; a *new* password wrap replaces the old one.
- One code per vault. Creating a second wrap is refused; to rotate the
  code you must understand you are replacing trust — currently: back up,
  keep the old code until the new wrap verifies (recovery wraps are
  single-slot by design for auditability).
