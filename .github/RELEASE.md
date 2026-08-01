# Stable release setup

The `Stable Release` workflow only accepts a tag matching the application
version, for example `v1.0.0` for `version: 1.0.0+1`.

Configure these GitHub Actions secrets before creating the first tag:

- `VELOGUARD_KEYSTORE_BASE64`: base64-encoded Android release keystore
- `VELOGUARD_KEYSTORE_PASSWORD`: keystore password
- `VELOGUARD_KEY_ALIAS`: release key alias
- `VELOGUARD_KEY_PASSWORD`: release key password

The same keystore must be retained for every release so Android can upgrade an
installed version. Add a matching section to `CHANGELOG.md`, then either run
`Stable Release` manually from the repository's default branch or push the
matching stable tag. Manual runs derive the tag from `pubspec.yaml`.

Published release assets are immutable. Increase the application version and
add a new changelog section for every subsequent release. Pre-release and
Nightly tags are rejected by design.
