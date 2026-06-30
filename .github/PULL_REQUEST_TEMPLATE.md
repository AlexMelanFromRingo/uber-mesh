<!-- Thanks for contributing to uber-mesh! Please read CONTRIBUTING.md first. -->

## Summary

<!-- What does this change and why? Link any issue / spec task (specs/001-uber-mesh-core/tasks.md). -->

## Type of change

- [ ] Bug fix
- [ ] New feature / capability
- [ ] Refactor / internal
- [ ] Docs / tooling / CI

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] New crypto / protocol / parser code ships with tests (KATs / property tests) — constitution Principle V
- [ ] No new `unsafe` (workspace denies it; `umesh-crypto` forbids it)
- [ ] No secrets (PSKs, identity seeds) added to logs, status output, errors, or fixtures
- [ ] Docs / `CHANGELOG.md` updated if behavior or interfaces changed

## Security considerations

<!-- For changes to umesh-crypto / umesh-obfs: what did you adversarially verify? Any new wire format,
     gate, or key-derivation change should describe the threat it addresses and what remains out of scope. -->
