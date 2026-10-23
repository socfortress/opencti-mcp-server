# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Container images are published to
`ghcr.io/socfortress/opencti-mcp-server` with matching tags.

## [0.1.0] - Unreleased

### Added
- Read-only MCP server for OpenCTI, built on plain async httpx with fixed GraphQL documents (no
  pycti and no raw-GraphQL tool). Tools: `lookup_observable`, `search_indicators`,
  `get_indicator`, `get_observable` (optionally with relationships) and `observable_indicators`,
  all annotated read-only.
- Guards in the server itself:
  - caller values only ever travel as GraphQL variables, in FilterGroup filters with one key each;
  - exact lookups on `value` and `hashes.<alg>` (case-insensitive `eq`); `search` is fuzzy
    discovery only;
  - id validation (a UUID or `<type>--<uuid>`), type allow-lists, and `first` capped by
    `OPENCTI_MAX_FIRST` (default 50);
  - a TLP ceiling, `OPENCTI_MAX_TLP` (default `TLP:AMBER+STRICT`): anything marked above it,
    nested indicators, observables, reports and relationships included, is withheld and counted
    in `withheld`; PAP markings are never read as TLP;
  - third-party text stripped of control and zero-width characters and capped (description 500,
    pattern 1000, 20 labels), and compact output capped by `MCP_MAX_OUTPUT_CHARS` with a
    `truncated` marker;
  - OpenCTI's HTTP-200 `errors` fail the call, partial data included, as structured tool errors
    (`not found:`, `bad request:`, `opencti refused the request:`, `opencti unavailable or timed out`,
    `opencti error:`); the token is never logged or returned.
- stdio and streamable HTTP transports; HTTP requires `MCP_AUTH_TOKEN`, which must differ from
  `OPENCTI_TOKEN`. `/healthz` is open; `/readyz` (behind the token) runs the deep health check and
  reports the OpenCTI version.
- Contract tests validating every document against the vendored OpenCTI 6.9.29 and 7.261023.1
  schemas, offline tests against a mock transport, and opt-in read-only live tests.
- A non-root multi-arch Docker image, `scripts/check_image.sh`, CI (`ci.yml`) and the GHCR publish
  workflow (`publish.yml`: `v*` tags, `release` environment, SBOM and provenance).
