# Release security (planning — not yet configured)

Source security does not imply release authenticity. Until the items below
exist, do NOT claim that a downloaded binary "is really from us":

- [ ] Protected `main` branch (required CI, required review, no force-push)
- [ ] Signed tags / signed releases (GPG or Sigstore)
- [ ] Published SHA-256 checksums per artifact
- [ ] Build provenance / attestation (e.g. GitHub attestations)
- [ ] Reproducible-build verification story
- [ ] Documented key-rotation procedure for signing keys

Current state: none of the above is configured. Distribute binaries only
through channels you control, and verify checksums out-of-band.
