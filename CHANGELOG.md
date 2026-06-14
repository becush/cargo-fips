# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cargo fips check` — primary CI gate for the `aws-lc-rs` backend: validated
  backend detection, FIPS-mode verification, competing-crypto detection, and
  declared-vs-validated version checks.
- `cargo fips oe` — operating-environment classification (tested /
  vendor-affirmable / off-certificate) from the target triple.
- `cargo fips guard` — build-flag guard over `RUSTFLAGS` and the resolved profile,
  with per-backend severity (source-built vs prebuilt-static).
- `cargo-fips-registry` — typed certificate registry; built-in data for CMVP
  certificate #4816 (AWS-LC FIPS), transcribed from the Security Policy.
- `cargo-fips-runtime` — runtime FIPS-assertion companion (skeleton).
- CI workflow: build, test, and exit-code assertions against fixtures.
