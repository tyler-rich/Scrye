# Third-party licenses

Scrye bundles the unmodified, official release binaries of the following
Apache-2.0-licensed projects. Each subdirectory contains that project's
`LICENSE` (and `NOTICE`, where the upstream repository ships one) as pulled
at the version pinned in `docker/Dockerfile`.

| Project | Version pinned  | Source                                     |
|---------|-----------------|---------------------------------------------|
| Trivy   | v0.71.2         | https://github.com/aquasecurity/trivy       |
| Grype   | v0.115.0        | https://github.com/anchore/grype            |
| Syft    | v1.46.0         | https://github.com/anchore/syft             |

Grype and Syft do not ship a `NOTICE` file upstream at these versions, so
only `LICENSE` is included for them.

None of these projects are modified before being bundled — Scrye orchestrates
their official binaries and parses their JSON output; it does not fork or
patch their source.
