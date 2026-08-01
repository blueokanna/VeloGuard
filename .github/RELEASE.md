# Stable release setup

The `Stable Release` workflow only accepts a tag matching the application
version, for example `v1.0.0` for `version: 1.0.0+1`.

Configure these GitHub Actions secrets before creating the first tag:

- `VELOGUARD_KEYSTORE_BASE64`: base64-encoded Android release keystore
- `VELOGUARD_KEYSTORE_PASSWORD`: keystore password
- `VELOGUARD_KEY_ALIAS`: release key alias
- `VELOGUARD_KEY_PASSWORD`: release key password

The same keystore must be retained for every release so Android can upgrade an
installed version. Add a matching section to `CHANGELOG.md`, then push the
stable tag. Pre-release and Nightly tags are rejected by design.
