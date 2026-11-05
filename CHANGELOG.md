# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `DdiClient::poll`, returning a `Poll` with hawkBit's polling interval and the open `Action`: a
  deployment or a cancel request.
- `DdiClient::feedback`, `DdiClient::progress` and `DdiClient::cancel_feedback` to report on
  actions; `Execution` covers every DDI execution status, so a device can reject a cancel or finish a
  download-only action with `Downloaded`.
- Target attributes, sent on the first poll and whenever hawkBit asks again.
- Links returned by the server are only followed when they point below the base URL, and
  `Token`'s `Debug` output hides the secret.
- `DdiClient::with_agent` to supply a custom `ureq::Agent`, for example to trust a private CA.
- Serde models for the deployment base resource: `DeploymentBase`, `Deployment` (with its
  download/update `Handling` and `MaintenanceWindow`), `Chunk`, `Artifact` (with filename, size and
  `Hashes`), `ArtifactLinks` and `Link`.
