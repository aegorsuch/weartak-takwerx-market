# TAKwerx Market catalog publisher

This repository owns publisher code and a reusable workflow; it does not
change the active WearTAK mirror or deploy production content by itself. The
published URL remains
`https://aegorsuch.github.io/weartak-wearos/catalog.json`, preserving the URL
and signing identity already trusted by watch builds.

The publisher reads only reviewed entries in
[`market-publisher/approved-repositories.json`](../market-publisher/approved-repositories.json).
It queries stable GitHub releases, enforces APK package and signer policy,
checks HTTPS redirects and download limits, computes SHA-256 digests, and
signs the catalog with Ed25519. It reuses unchanged entries only from the
previous catalog after verifying that catalog's signature.

## Reusable workflow

The workflow at
`.github/workflows/publish-market-catalog.yml` is `workflow_call`-only. It
checks out publisher source at the caller-provided immutable `publisher_ref`,
runs tests, builds the signed catalog, and uses the caller workflow's GitHub
context and token permissions for Pages deployment. GitHub documents that
the `github` context in a called workflow is associated with its caller; Pages
therefore remains associated with the caller repository.

The caller must grant `contents: read`, `pages: write`, and `id-token: write`
to the reusable-workflow job and pass its existing public key as
`market_catalog_public_key`. On trusted runs, pass the existing signing secret
explicitly as `catalog_signing_key`; tests can run without this secret. Keep
the private key in the existing mirror repository. Do not create a
same-named `catalog_signing_key` secret in the `github-pages` environment,
since environment secrets take precedence over a passed secret. The called
workflow refuses publication for pull requests and `pull_request_target`;
publication also requires the caller ref to be `main`.

After this repository has a reviewed commit SHA, replace `SHA` below with
that exact 40-character commit in both places. Keep a test-only call for pull
requests with no secret, and use the secret-bearing call only for trusted
events:

```yaml
jobs:
  test-publisher:
    if: github.event_name == 'pull_request'
    permissions:
      contents: read
    uses: aegorsuch/weartak-takwerx-market/.github/workflows/publish-market-catalog.yml@SHA
    with:
      publisher_ref: SHA
      market_catalog_public_key: ${{ vars.MARKET_CATALOG_PUBLIC_KEY }}

  publish:
    if: github.event_name != 'pull_request' && github.event_name != 'pull_request_target' && github.ref == 'refs/heads/main'
    permissions:
      contents: read
      pages: write
      id-token: write
    uses: aegorsuch/weartak-takwerx-market/.github/workflows/publish-market-catalog.yml@SHA
    with:
      publisher_ref: SHA
      market_catalog_public_key: ${{ vars.MARKET_CATALOG_PUBLIC_KEY }}
    secrets:
      catalog_signing_key: ${{ secrets.MARKET_CATALOG_SIGNING_KEY }}
```

Keep the existing mirror's schedule and other trusted triggers. Preserve its
GitHub Pages configuration and `github-pages` environment. Do not pass the
signing secret on pull-request runs. Pinning the workflow and checkout to the
same reviewed SHA means later publisher changes cannot silently acquire the
secret; every pin update should be reviewed as privileged code.

## Signed format and limits

The output is the existing JSON envelope: Base64 payload and Base64 Ed25519
signature. Payload schema stays version 1. HTTPS is required for catalog and
APK URLs; redirects cannot downgrade to HTTP. APKs are capped at 250 MiB to
match client limits. See the WearTAK market documentation in
[`weartak-wearos`](https://github.com/aegorsuch/weartak-wearos) for client
verification and installation behavior.
