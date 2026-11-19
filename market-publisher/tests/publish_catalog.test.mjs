import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, verify } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  fetchPreviousCatalog,
  buildCatalog,
  MAX_APK_BYTES,
  parseSignerSha256,
  signCatalog,
} from "../publish_catalog.mjs";

const trackerConfig = JSON.parse(await readFile(
  new URL("../approved-tracker-repositories.json", import.meta.url),
  "utf8",
));

function source(overrides = {}) {
  return {
    owner: "aegorsuch",
    repo: "weartak-plugin-example",
    id: "example",
    name: "Example",
    description: "Example WearTAK plugin.",
    publisher: "aegorsuch",
    publisherType: "community",
    hostUpdate: false,
    packageName: "org.example.plugin",
    expectedSignerSha256: "a".repeat(64),
    minHostVersionCode: 5840000,
    maxHostVersionCode: null,
    assetPattern: "^WearTAK-Plugin-Example-.*\\.apk$",
    ...overrides,
  };
}

function fetchForRelease(assets, { releaseOverrides = {}, assetBytes = new Map() } = {}) {
  return async (url) => {
    if (url.toString().startsWith("https://api.github.com/")) {
      return new Response(JSON.stringify({
        draft: false,
        prerelease: false,
        assets,
        ...releaseOverrides,
      }), { status: 200 });
    }
    const bytes = assetBytes.get(new URL(url).pathname.split("/").pop());
    if (!bytes) return new Response(null, { status: 404 });
    return new Response(bytes, { status: 200 });
  };
}

test("builds entries only from stable APK assets and uses verified metadata", async () => {
  const assets = [
    {
      name: "WearTAK-Plugin-Example-1.apk",
      size: 3,
      browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/WearTAK-Plugin-Example-1.apk",
    },
    {
      name: "provenance.json",
      size: 3,
      browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/provenance.json",
    },
  ];
  const apk = Buffer.from([1, 2, 3]);
  const catalog = await buildCatalog(
    { schemaVersion: 1, repositories: [source()] },
    {
      fetchImpl: fetchForRelease(assets, {
        assetBytes: new Map([[assets[0].name, apk]]),
      }),
      inspect: async () => ({
        packageName: "org.example.plugin",
        versionName: "1.2.0",
        versionCode: 12,
        signerSha256: "a".repeat(64),
      }),
    },
  );

  assert.equal(catalog.plugins.length, 1);
  const { publisherReleaseFingerprint, ...plugin } = catalog.plugins[0];
  assert.match(publisherReleaseFingerprint, /^[0-9a-f]{64}$/);
  assert.deepEqual(plugin, {
    id: "example",
    name: "Example",
    description: "Example WearTAK plugin.",
    publisher: "aegorsuch",
    publisherType: "community",
    packageName: "org.example.plugin",
    versionName: "1.2.0",
    versionCode: 12,
    minHostVersionCode: 5840000,
    maxHostVersionCode: null,
    apkUrl: assets[0].browser_download_url,
    apkSha256: "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
    signerSha256: "a".repeat(64),
    sourceUrl: "https://github.com/aegorsuch/weartak-plugin-example",
    hostUpdate: false,
  });
});

test("rejects releases signed by a certificate outside the approved profile", async () => {
  const asset = {
    name: "WearTAK-Plugin-Example-1.apk",
    size: 3,
    browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/WearTAK-Plugin-Example-1.apk",
  };
  await assert.rejects(
    buildCatalog(
      { schemaVersion: 1, repositories: [source()] },
      {
        fetchImpl: fetchForRelease([asset], {
          assetBytes: new Map([[asset.name, Buffer.from("apk")]]),
        }),
        inspect: async () => ({
          packageName: "org.example.plugin",
          versionName: "1.2.0",
          versionCode: 12,
          signerSha256: "b".repeat(64),
        }),
      },
    ),
    /APK signer mismatch/,
  );
});

test("reuses unchanged approved release metadata without downloading APK again", async () => {
  const assets = [{
    id: 17,
    name: "WearTAK-Plugin-Example-1.apk",
    size: 3,
    updated_at: "2026-01-01T00:00:00Z",
    browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/WearTAK-Plugin-Example-1.apk",
  }];
  const apk = Buffer.from([1, 2, 3]);
  const fetchImpl = fetchForRelease(assets, {
    assetBytes: new Map([[assets[0].name, apk]]),
  });
  const firstCatalog = await buildCatalog(
    { schemaVersion: 1, repositories: [source()] },
    {
      fetchImpl,
      inspect: async () => ({
        packageName: "org.example.plugin",
        versionName: "1.2.0",
        versionCode: 12,
        signerSha256: "a".repeat(64),
      }),
    },
  );
  const secondCatalog = await buildCatalog(
    { schemaVersion: 1, repositories: [source()] },
    {
      fetchImpl,
      previousCatalog: firstCatalog,
      inspect: async () => assert.fail("Unchanged release must reuse signed catalog metadata."),
    },
  );
  assert.deepEqual(secondCatalog, firstCatalog);
});

test("refreshes the approved WearOS host display name without changing identity or attribution", async () => {
  const config = JSON.parse(await readFile(
    new URL("../approved-repositories.json", import.meta.url),
    "utf8",
  ));
  const host = config.repositories.find((entry) => entry.id === "weartak");
  assert.ok(host);
  const asset = {
    name: "WearTAK-5.8.4-p736.apk",
    size: 3,
    browser_download_url: "https://github.com/aegorsuch/weartak-wearos/releases/download/v1/WearTAK-5.8.4-p736.apk",
  };
  let inspections = 0;
  const options = {
    fetchImpl: fetchForRelease([asset], {
      assetBytes: new Map([[asset.name, Buffer.from("apk")]]),
    }),
    inspect: async () => {
      inspections += 1;
      return {
        packageName: "com.aitech.weartak_civ",
        versionName: "5.8.4-p736",
        versionCode: 5840736,
        signerSha256: "a".repeat(64),
      };
    },
  };
  const previousCatalog = await buildCatalog(
    { schemaVersion: 1, repositories: [{ ...host, name: "WearTAK" }] },
    options,
  );
  const catalog = await buildCatalog(
    { schemaVersion: 1, repositories: [host] },
    { ...options, previousCatalog },
  );

  assert.equal(inspections, 2);
  assert.deepEqual(catalog.plugins, [{
    ...previousCatalog.plugins[0],
    name: "WearTAK-WearOS",
  }]);
});

test("builds the approved Tracker host only for its explicit isolated target", async () => {
  const asset = {
    name: "WearTAK-Tracker-5.8.4-p62.apk",
    size: 3,
    browser_download_url: "https://github.com/aegorsuch/weartak-tracker/releases/download/takgov-pipeline/WearTAK-Tracker-5.8.4-p62.apk",
  };
  const requests = [];
  const fetchImpl = fetchForRelease([asset], {
    assetBytes: new Map([[asset.name, Buffer.from("apk")]]),
  });
  const catalog = await buildCatalog(trackerConfig, {
    target: "tracker",
    fetchImpl: async (url) => {
      requests.push(url.toString());
      return fetchImpl(url);
    },
    inspect: async () => ({
      packageName: "com.tak.weartak_tracker",
      versionName: "5.8.4-p62",
      versionCode: 5860062,
      signerSha256: trackerConfig.repositories[0].expectedSignerSha256,
    }),
  });

  assert.equal(catalog.plugins.length, 1);
  assert.deepEqual({
    id: catalog.plugins[0].id,
    name: catalog.plugins[0].name,
    publisher: catalog.plugins[0].publisher,
    publisherType: catalog.plugins[0].publisherType,
    packageName: catalog.plugins[0].packageName,
    hostUpdate: catalog.plugins[0].hostUpdate,
    signerSha256: catalog.plugins[0].signerSha256,
  }, {
    id: "weartak-tracker",
    name: "WearTAK-Tracker",
    publisher: "WearTAK",
    publisherType: "official",
    packageName: "com.tak.weartak_tracker",
    hostUpdate: true,
    signerSha256: "430f146736b3dafc44157ff0b62836d16202244da17209176cb335ef0e63f2ec",
  });
  assert.deepEqual(requests, [
    "https://api.github.com/repos/aegorsuch/weartak-tracker/releases/latest",
    asset.browser_download_url,
  ]);
});

test("the full default WearOS catalog excludes Tracker and preserves approved plugin metadata", async () => {
  const config = JSON.parse(await readFile(
    new URL("../approved-repositories.json", import.meta.url),
    "utf8",
  ));
  const catalog = await buildCatalog(config, {
    fetchImpl: async (url) => {
      const request = new URL(url);
      const repository = request.pathname.split("/")[request.hostname === "api.github.com" ? 3 : 2];
      assert.notEqual(repository, "weartak-tracker");
      const approved = config.repositories.find((entry) => entry.repo === repository);
      assert.ok(approved);
      if (request.hostname === "api.github.com") {
        const name = approved.hostUpdate ? "WearTAK-1.apk" : `WearTAK-Plugin-${approved.name}-1.apk`;
        return new Response(JSON.stringify({
          draft: false,
          prerelease: false,
          assets: [{
            name,
            size: 3,
            browser_download_url: `https://github.com/${approved.owner}/${approved.repo}/releases/download/v1/${name}`,
          }],
        }));
      }
      return new Response(Buffer.from(repository));
    },
    inspect: async (bytes) => {
      const approved = config.repositories.find((entry) => entry.repo === bytes.toString());
      assert.ok(approved);
      return {
        packageName: approved.packageName,
        versionName: "1.0",
        versionCode: 1,
        signerSha256: approved.expectedSignerSha256 || "a".repeat(64),
      };
    },
  });
  assert.equal(catalog.plugins.length, config.repositories.length);
  assert.equal(catalog.plugins.some((entry) => entry.packageName === "com.tak.weartak_tracker"), false);
  for (const entry of catalog.plugins) {
    const approved = config.repositories.find((source) => source.id === entry.id);
    assert.equal(entry.name, approved.name);
    assert.equal(entry.publisher, approved.publisher);
    assert.equal(entry.packageName, approved.packageName);
  }
});

test("rejects cross-target approvals and host impersonation before making requests", async () => {
  const wearosConfig = JSON.parse(await readFile(
    new URL("../approved-repositories.json", import.meta.url),
    "utf8",
  ));
  const fetchImpl = async () => assert.fail("Invalid host policy must fail before network access.");
  await assert.rejects(buildCatalog(trackerConfig, { fetchImpl }), /does not match the catalog target/);
  await assert.rejects(
    buildCatalog(wearosConfig, { target: "tracker", fetchImpl }),
    /does not match the catalog target/,
  );
  await assert.rejects(
    buildCatalog(trackerConfig, { target: "unknown", fetchImpl }),
    /Catalog target/,
  );

  for (const [target, config, foreignHost] of [
    ["wearos", wearosConfig, trackerConfig.repositories[0]],
    ["tracker", trackerConfig, wearosConfig.repositories[0]],
  ]) {
    await assert.rejects(buildCatalog({
      ...config,
      repositories: [...config.repositories, foreignHost],
    }, { target, fetchImpl }), /Only the official/);
  }

  for (const overrides of [
    { repo: "unapproved-tracker" },
    { packageName: "org.example.other" },
    { expectedSignerSha256: undefined },
    { hostUpdate: false, publisherType: "community" },
  ]) {
    await assert.rejects(buildCatalog({
      ...trackerConfig,
      repositories: [{ ...trackerConfig.repositories[0], ...overrides }],
    }, { target: "tracker", fetchImpl }), /official|approved signer|host package/);
  }
});

test("Tracker verification rejects wrong APK packages and signers", async () => {
  const asset = {
    name: "WearTAK-Tracker-5.8.4-p62.apk",
    size: 3,
    browser_download_url: "https://github.com/aegorsuch/weartak-tracker/releases/download/takgov-pipeline/WearTAK-Tracker-5.8.4-p62.apk",
  };
  for (const overrides of [
    { packageName: "com.aitech.weartak_civ" },
    { signerSha256: "a".repeat(64) },
  ]) {
    await assert.rejects(buildCatalog(trackerConfig, {
      target: "tracker",
      fetchImpl: fetchForRelease([asset], {
        assetBytes: new Map([[asset.name, Buffer.from("apk")]]),
      }),
      inspect: async () => ({
        packageName: "com.tak.weartak_tracker",
        versionName: "5.8.4-p62",
        versionCode: 5860062,
        signerSha256: trackerConfig.repositories[0].expectedSignerSha256,
        ...overrides,
      }),
    }), /package mismatch|signer mismatch/);
  }
});

test("Tracker catalog fails closed without an eligible host APK", async () => {
  await assert.rejects(buildCatalog(trackerConfig, {
    target: "tracker",
    fetchImpl: fetchForRelease([{
      name: "WearTAK-Tracker-5.8.4-p61.apk",
      size: 282357132,
      browser_download_url: "https://github.com/aegorsuch/weartak-tracker/releases/download/takgov-pipeline/WearTAK-Tracker-5.8.4-p61.apk",
    }]),
    inspect: async () => assert.fail("Oversized Tracker APK must not be downloaded."),
  }), /Tracker host APK exceeds the 250 MiB/);

  await assert.rejects(buildCatalog(trackerConfig, {
    target: "tracker",
    fetchImpl: fetchForRelease([], { releaseOverrides: { prerelease: true } }),
  }), /requires an eligible verified host APK/);
});

test("Tracker CLI selects its separate approvals and does not write an oversized-host catalog", async (t) => {
  const outputDir = await mkdtemp(path.join(tmpdir(), "weartak-tracker-catalog-test-"));
  t.after(() => rm(outputDir, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const preload = `
    globalThis.fetch = async (url) => {
      if (url.toString() === "https://aegorsuch.github.io/weartak-tracker/catalog.json") {
        return new Response(null, { status: 404 });
      }
      if (url.toString() === "https://api.github.com/repos/aegorsuch/weartak-tracker/releases/latest") {
        return new Response(JSON.stringify({
          draft: false,
          prerelease: false,
          assets: [{
            name: "WearTAK-Tracker-5.8.4-p61.apk",
            size: 282357132,
            browser_download_url: "https://github.com/aegorsuch/weartak-tracker/releases/download/takgov-pipeline/WearTAK-Tracker-5.8.4-p61.apk"
          }]
        }));
      }
      throw new Error("Unexpected request: " + url);
    };
  `;
  const result = spawnSync(process.execPath, [
    "--import",
    `data:text/javascript,${encodeURIComponent(preload)}`,
    fileURLToPath(new URL("../publish_catalog.mjs", import.meta.url)),
  ], {
    env: {
      ...process.env,
      MARKET_CATALOG_TARGET: "tracker",
      MARKET_APPROVED_REPOSITORIES: "",
      MARKET_CATALOG_SIGNING_KEY: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      MARKET_CATALOG_PUBLIC_KEY: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
      MARKET_OUTPUT_DIR: outputDir,
    },
    encoding: "utf8",
    timeout: 10000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Tracker host APK exceeds the 250 MiB/);
  await assert.rejects(access(path.join(outputDir, "catalog.json")), { code: "ENOENT" });
});

test("skips prereleases and fails when an approved repository has no stable release", async () => {
  const prereleaseCatalog = await buildCatalog(
    { schemaVersion: 1, repositories: [source()] },
    {
      fetchImpl: fetchForRelease([], { releaseOverrides: { prerelease: true } }),
      inspect: async () => assert.fail("Prerelease must not be inspected."),
    },
  );
  assert.deepEqual(prereleaseCatalog.plugins, []);

  await assert.rejects(
    buildCatalog(
      { schemaVersion: 1, repositories: [source()] },
      { fetchImpl: async () => new Response(null, { status: 404 }) },
    ),
    /has no stable release/,
  );
});

test("does not fetch repositories listed only as pending", async () => {
  const catalog = await buildCatalog({
    schemaVersion: 1,
    repositories: [],
    pendingRepositories: ["example-owner/weartak-plugin-not-listed"],
  }, {
    fetchImpl: async () => assert.fail("Pending repository must not be queried."),
  });
  assert.deepEqual(catalog.plugins, []);
});

test("skips APKs larger than the client download limit", async () => {
  assert.equal(MAX_APK_BYTES, 250 * 1024 * 1024);
  const asset = {
    name: "WearTAK-Plugin-Example-1.apk",
    size: MAX_APK_BYTES + 1,
    browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/app.apk",
  };
  const catalog = await buildCatalog(
    { schemaVersion: 1, repositories: [source()] },
    {
      fetchImpl: fetchForRelease([asset]),
      inspect: async () => assert.fail("Oversized APK must not be downloaded."),
    },
  );
  assert.deepEqual(catalog.plugins, []);
});

test("rejects insecure release redirects and duplicate packages", async () => {
  const redirectAssets = [{
    name: "WearTAK-Plugin-Example-1.apk",
    size: 1,
    browser_download_url: "https://github.com/aegorsuch/weartak-plugin-example/releases/download/v1/app.apk",
  }];
  const redirectFetch = async (url) => {
    if (url.toString().startsWith("https://api.github.com/")) {
      return new Response(JSON.stringify({
        draft: false,
        prerelease: false,
        assets: redirectAssets,
      }), { status: 200 });
    }
    return new Response(null, {
      status: 302,
      headers: { location: "http://malicious.example/app.apk" },
    });
  };
  await assert.rejects(
    buildCatalog(
      { schemaVersion: 1, repositories: [source()] },
      { fetchImpl: redirectFetch },
    ),
    /HTTPS URL/,
  );

  const duplicate = source({ owner: "another-owner", repo: "another-plugin", id: "another" });
  await assert.rejects(
    buildCatalog(
      {
        schemaVersion: 1,
        repositories: [
          source({ expectedSignerSha256: "b".repeat(64) }),
          { ...duplicate, packageName: "org.example.plugin", expectedSignerSha256: "b".repeat(64) },
        ],
      },
      {
        fetchImpl: async (url) => {
          const parsed = new URL(url);
          if (parsed.hostname === "api.github.com") {
            const repo = parsed.pathname.split("/")[3];
            const asset = {
              name: "WearTAK-Plugin-Example-1.apk",
              size: 3,
              browser_download_url: `https://github.com/${parsed.pathname.split("/")[2]}/${repo}/releases/download/v1/app.apk`,
            };
            return new Response(JSON.stringify({
              draft: false,
              prerelease: false,
              assets: [asset],
            }), { status: 200 });
          }
          return new Response(Buffer.from("apk"), { status: 200 });
        },
        inspect: async () => ({
          packageName: "org.example.plugin",
          versionName: "1.0",
          versionCode: 1,
          signerSha256: "b".repeat(64),
        }),
      },
    ),
    /duplicate APK package names/,
  );
});

test("extracts a single signer digest and rejects ambiguous signer sets", () => {
  assert.equal(
    parseSignerSha256("Signer #1 certificate SHA-256 digest: AA:".concat("AB:".repeat(30), "AC")),
    "aa".concat("ab".repeat(30), "ac"),
  );
  assert.throws(
    () => parseSignerSha256("Signer #1 certificate SHA-256 digest: " + "aa".repeat(32) +
      "\nSigner #2 certificate SHA-256 digest: " + "bb".repeat(32)),
    /exactly one/,
  );
});

test("signs exact catalog bytes with the configured Ed25519 key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBase64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const catalog = { schemaVersion: 1, plugins: [] };
  const envelope = JSON.parse(signCatalog(catalog, privateKeyPem, publicKeyBase64));
  const payload = Buffer.from(envelope.payload, "base64");

  assert.deepEqual(JSON.parse(payload.toString("utf8")), catalog);
  assert.equal(
    verify(null, payload, publicKey, Buffer.from(envelope.signature, "base64")),
    true,
  );
  assert.throws(
    () => signCatalog(catalog, privateKeyPem, "invalid"),
    /does not match/,
  );
});

test("accepts only a valid previously signed catalog", async () => {
  const keys = generateKeyPairSync("ed25519");
  const publicKeyBase64 = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const privateKeyPem = keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const envelope = signCatalog({ schemaVersion: 1, plugins: [] }, privateKeyPem, publicKeyBase64);
  const catalog = await fetchPreviousCatalog(
    async () => new Response(envelope, { status: 200 }),
    publicKeyBase64,
  );
  assert.deepEqual(catalog, { schemaVersion: 1, plugins: [] });

  await assert.rejects(
    fetchPreviousCatalog(
      async () => new Response(envelope.replace(/.$/, "x"), { status: 200 }),
      publicKeyBase64,
    ),
    /signature is invalid|envelope is invalid/,
  );
});

test("previous-catalog requests use isolated target URLs and still verify signatures", async () => {
  const keys = generateKeyPairSync("ed25519");
  const publicKeyBase64 = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const privateKeyPem = keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const envelope = signCatalog({ schemaVersion: 1, plugins: [] }, privateKeyPem, publicKeyBase64);
  const requests = [];
  const fetchImpl = async (url) => {
    requests.push(url.toString());
    return new Response(envelope);
  };
  await fetchPreviousCatalog(fetchImpl, publicKeyBase64);
  await fetchPreviousCatalog(fetchImpl, publicKeyBase64, "tracker");
  assert.deepEqual(requests, [
    "https://aegorsuch.github.io/weartak-wearos/catalog.json",
    "https://aegorsuch.github.io/weartak-tracker/catalog.json",
  ]);
  const foreignKeys = generateKeyPairSync("ed25519");
  const foreignPublicKey = foreignKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  await assert.rejects(
    fetchPreviousCatalog(fetchImpl, foreignPublicKey, "tracker"),
    /signature is invalid/,
  );
});
