# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `DdiClient` for polling a controller's pending deployment (accepting cancel requests), reporting
  feedback and progress, and sending target attributes.
- Links returned by the server are only followed when they point below the base URL, and
  `Token`'s `Debug` output hides the secret.
- `DdiClient::with_agent` to supply a custom `ureq::Agent`, for example to trust a private CA.
- Serde models for the deployment base resource: `DeploymentBase`, `Deployment`, `Chunk`,
  `Artifact`, `ArtifactLinks` and `Link`.
