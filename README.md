# WearTAK TAKwerx Market Publisher

## Purpose and Capabilities

Standalone source and reusable GitHub Actions workflow for building and
publishing the signed TAKwerx Market catalog. The publisher reads a reviewed
repository allowlist, validates stable GitHub release APKs, and signs catalog
metadata with Ed25519.

## Status

Staged for later integration with the existing WearTAK mirror workflow. This
repository does not currently deploy a catalog or change the catalog URL used
by watches.

## Point of Contacts

Repository maintainers.

## Ports Required

Outbound HTTPS to the GitHub API, GitHub release assets, and the existing
published catalog. No inbound ports.

## Equipment Required

None beyond GitHub Actions hosted runners.

## Equipment Supported

Ubuntu GitHub Actions runners with Node.js and Android SDK build-tools 35.0.0.

## Compilation

No compilation step. Run focused publisher tests with:

```sh
node --test market-publisher/tests/publish_catalog.test.mjs
```

## Developer Notes

The current publisher URL remains
`https://aegorsuch.github.io/weartak-wearos/catalog.json`. The reusable
workflow runs in its caller's repository context so GitHub Pages remains
deployed by the existing mirror. The caller must pass the existing signing
secret explicitly and provide this repository's immutable commit SHA both as
the reusable workflow ref and `publisher_ref`.

Do not pass signing secrets from pull-request workflows. Pin the called
workflow and publisher checkout to a reviewed commit SHA; changing that pin
grants the selected publisher revision access to the signing key. Keep
`MARKET_CATALOG_SIGNING_KEY` in the mirror repository and its public key
unchanged. See [publisher and rollout details](docs/TAKWERX_MARKET.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
