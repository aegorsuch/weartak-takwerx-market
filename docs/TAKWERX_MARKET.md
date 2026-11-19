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

## Host display metadata

The approved WearOS host entry uses display name `WearTAK-WearOS`. Its
identity remains `id: weartak`, `packageName: com.aitech.weartak_civ`,
`publisherType: official`, and `hostUpdate: true`, sourced from
`aegorsuch/weartak-wearos`. The publisher attribution remains `WearTAK`.
Clients may hide redundant host-row attribution after validating the host
identity; the signed catalog retains that attribution.

Tracker is approved only in
[`approved-tracker-repositories.json`](../market-publisher/approved-tracker-repositories.json),
not the WearOS approval file. Its identity is `id: weartak-tracker`,
`packageName: com.tak.weartak_tracker`, `publisherType: official`, and
`hostUpdate: true`, sourced from `aegorsuch/weartak-tracker`. Its display name
is `WearTAK-Tracker` and publisher attribution is `WearTAK`. Tracker APKs must
match the independently verified certificate SHA-256:

```text
430f146736b3dafc44157ff0b62836d16202244da17209176cb335ef0e63f2ec
```

Plugin names and publisher attribution in the WearOS approval file are
unchanged. No WearOS plugins are implicitly approved for Tracker; adding
compatible plugins requires review of Tracker's separate approval file.

## Isolated catalog targets

`MARKET_CATALOG_TARGET` selects `wearos` (default) or `tracker`. The reusable
workflow exposes the same selection as `catalog_target`. Each target selects
its own approval file and previous signed catalog URL:

| Target | Deployment caller | Catalog URL |
| --- | --- | --- |
| `wearos` | `aegorsuch/weartak-wearos` | `https://aegorsuch.github.io/weartak-wearos/catalog.json` (unchanged) |
| `tracker` | `aegorsuch/weartak-tracker` | `https://aegorsuch.github.io/weartak-tracker/catalog.json` (planned; not activated) |

Both use `catalog.json` within separate caller-owned Pages sites. The
workflow rejects a caller/target mismatch before checking out publisher code
or using the signing key. Never deploy both targets to the same Pages site:
a Pages deployment replaces that site's artifact. The existing WearOS
caller needs no new input. Local output defaults are separate as well:
`market-publisher/site` for WearOS and `market-publisher/tracker-site` for
Tracker. Keep overrides via `MARKET_OUTPUT_DIR` separate.

Tracker's approval file declares `catalogTarget: tracker`; configuration and
selected target must match. Host policy binds each target to its exact
official repository and package. Known host packages cannot be submitted as
community plugins. The publisher rejects foreign host approvals instead of
relying on client-side filtering. Cache reuse fetches and signature-verifies
only the selected target's previous catalog. Signed envelope and payload
schema remain unchanged.

### Tracker activation (not performed)

The canonical signed p65 release resolves the historical APK-size blocker
described below. Tracker generation deliberately fails if no eligible verified
host APK can be included; it must not deploy an empty catalog in place of its
host update.

After review and explicit release authorization, publish a publisher revision
and configure a caller in the Tracker mirror on trusted `main`, pinned to that
revision. Set `catalog_target: tracker` in the reusable-workflow call, retain
the explicit public-key input and signing-secret mapping shown below, and
configure Tracker's own Pages environment. Provision its intended catalog
signing identity explicitly; the APK signer pin above is not a catalog public
key. Do not copy, rotate, or change the WearOS catalog secret or public key.

After the isolated endpoint is deployed and its signature verified, update
Tracker's canonical build configuration to that URL and its matching catalog
public key. Existing Tracker builds configured for the WearOS URL will not
switch automatically. Do not add Tracker to the WearOS approval file or
change WearOS's URL/key. These publication, key provisioning, Pages, and client-build configuration
steps require separate deployment authorization.

## Tracker APK-size investigation

The canonical signed
[`WearTAK-Tracker-5.8.4-p65.apk`](https://github.com/aegorsuch/weartak-tracker/releases/tag/takgov-pipeline)
resolves the size blocker: 143,355,363 bytes (136.71 MiB), version code
`5860065`, version name `5.8.4-p65+750ebead`. TAK.gov
[pipeline 65](https://git.tak.gov/core/weartak-core/weartak-tracker/-/pipelines/1872308)
built source `750ebead9db232c86c539ef3ea730e46cb77c990`. Independent
verification of its job artifact confirmed the sole pinned APK signer above,
package `com.tak.weartak_tracker`, and exactly `arm64-v8a` and `armeabi-v7a`
native libraries. The GitHub mirror reports the same size and SHA-256:

```text
80611e2b9aa91eeb2bee4d9b81020f9d560da0443ba6797484c6b5f7e126aba4
```

Both publisher and client retain the 262,144,000-byte cap. The following
p61 findings are historical, not the current release's eligibility.

The previously verified stable release
[`WearTAK-Tracker-5.8.4-p61.apk`](https://github.com/aegorsuch/weartak-tracker/releases/tag/takgov-pipeline)
is 282,357,132 bytes (269.28 MiB). It exceeds the publisher and Tracker client
limit of 262,144,000 bytes (250 MiB) by 20,213,132 bytes (19.28 MiB).
Both limits remain unchanged. The client checks both declared content length
and streamed byte count; raising only the publisher cap would still produce
an undownloadable update.

The APK SHA-256 matches GitHub asset metadata and the canonical release
receipt:

```text
aa2e1933dff3b0c6ca27767b8fce1f8b3afee47495356f2566677d784d4b9b6c
```

`apksigner verify --verbose --print-certs` verified one v2 signer matching
Tracker's pinned certificate. `apkanalyzer` verified package
`com.tak.weartak_tracker`, version code `5860061`, and version name
`5.8.4-p61+7a871d8f`. The signer also matches the
[canonical source's CI check at the release commit](https://github.com/aegorsuch/weartak-tracker/blob/7a871d8f7c387017b6f436b32ccd715b7f08b55c/.gitlab-ci.yml).

ZIP inspection shows native libraries are stored uncompressed for four ABIs:

| APK directory | Stored bytes |
| --- | ---: |
| `lib/arm64-v8a` | 80,777,856 |
| `lib/x86_64` | 73,167,880 |
| `lib/x86` | 65,789,396 |
| `lib/armeabi-v7a` | 56,303,992 |

`libdittoffi.so` dominates each ABI. The two x86 directories alone occupy
138,957,276 bytes. A reviewed canonical ABI-specific or ARM-only release
could fit without raising download limits, if it preserves supported watch
architectures. Rebuild and sign canonically, then reverify final size,
package, signer, and digest; never edit the signed APK to remove libraries.
No Tracker build settings or client limits were changed here.

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
