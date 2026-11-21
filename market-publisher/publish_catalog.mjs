import { execFile as execFileCallback } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFile = promisify(execFileCallback);
export const MAX_APK_BYTES = 250 * 1024 * 1024;
const MAX_CATALOG_BYTES = 512 * 1024;
const MAX_PLUGINS = 200;
const CATALOG_TARGETS = new Map([
  ["wearos", {
    productId: "weartak-wearos",
    repository: "aegorsuch/weartak-wearos",
    packageName: "com.aitech.weartak_civ",
    configFile: "approved-repositories.json",
    catalogUrl: "https://aegorsuch.github.io/weartak-wearos/catalog.json",
    outputDirectory: "site",
  }],
  ["tracker", {
    productId: "weartak-tracker",
    repository: "aegorsuch/weartak-tracker",
    packageName: "com.tak.weartak_tracker",
    configFile: "approved-tracker-repositories.json",
    catalogUrl: "https://aegorsuch.github.io/weartak-tracker/catalog.json",
    outputDirectory: "tracker-site",
  }],
]);
const PRODUCT_IDS = new Set([...CATALOG_TARGETS.values()].map((profile) => profile.productId));
const EDITION_IDS = new Set(["civ", "mil"]);
const PACKAGE_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function catalogTarget(target) {
  const profile = CATALOG_TARGETS.get(target);
  if (!profile) throw new Error("Catalog target must be 'wearos', 'tracker', or 'shared'.");
  return profile;
}

function requireHttps(rawUrl, label) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`${label} is not a valid URL.`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error(`${label} must be an HTTPS URL without credentials or a fragment.`);
  }
  return url;
}

async function fetchHttps(fetchImpl, rawUrl, accept, { githubAssetRedirects = false } = {}) {
  let url = requireHttps(rawUrl, "Request URL");
  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    const headers = {
      Accept: accept,
      "User-Agent": "WearTAK-Market-Catalog-Publisher",
    };
    if ((url.hostname === "api.github.com" || url.hostname === "github.com") &&
        process.env.GITHUB_TOKEN) {
      headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const response = await fetchImpl(url, {
      headers,
      redirect: "manual",
    });
    if (!REDIRECT_STATUSES.has(response.status)) return response;
    const location = response.headers.get("location");
    await response.body?.cancel();
    if (!location || redirectCount === 5) {
      throw new Error("Release request exceeded redirect limit.");
    }
    const nextUrl = requireHttps(new URL(location, url).toString(), "Redirect URL");
    if (githubAssetRedirects &&
        nextUrl.hostname !== "github.com" &&
        nextUrl.hostname !== "githubusercontent.com" &&
        !nextUrl.hostname.endsWith(".githubusercontent.com")) {
      throw new Error("GitHub release APK redirected to an untrusted host.");
    }
    url = nextUrl;
  }
  throw new Error("Release request exceeded redirect limit.");
}

async function getJson(fetchImpl, url, repository) {
  const response = await fetchHttps(fetchImpl, url, "application/vnd.github+json");
  if (response.status === 404) return null;
  if (!response.ok) {
    const details = [];
    for (const [header, maximum] of [
      ["x-ratelimit-remaining", 1000000000],
      ["x-ratelimit-reset", 9999999999],
      ["retry-after", 86400],
    ]) {
      const value = response.headers.get(header);
      if (value !== null && /^[0-9]{1,10}$/.test(value) && Number(value) <= maximum) {
        details.push(`${header}=${value}`);
      }
    }
    const requestId = response.headers.get("x-github-request-id");
    if (requestId && /^[a-f0-9]{1,16}(?::[a-f0-9]{1,16}){3,5}$/i.test(requestId)) {
      details.push(`x-github-request-id=${requestId}`);
    }
    const suffix = details.length ? `; ${details.join("; ")}` : "";
    throw new Error(`GitHub release API request failed for '${repository}' (HTTP ${response.status}${suffix}).`);
  }
  return response.json();
}

export async function fetchPreviousCatalog(fetchImpl, publicKeyBase64, target = "wearos") {
  const response = await fetchHttps(fetchImpl, catalogTarget(target).catalogUrl, "application/json");
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Previously published catalog request failed (HTTP ${response.status}).`);
  }
  const bytes = await readLimitedBody(response, MAX_CATALOG_BYTES, "Previously published catalog");
  let envelope;
  let payload;
  let signature;
  let publicKey;
  try {
    envelope = JSON.parse(bytes.toString("utf8"));
    payload = Buffer.from(envelope.payload, "base64");
    signature = Buffer.from(envelope.signature, "base64");
    publicKey = createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Error("Previously published catalog envelope is invalid.");
  }
  if (!verify(null, payload, publicKey, signature)) {
    throw new Error("Previously published catalog signature is invalid.");
  }
  let catalog;
  try {
    catalog = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new Error("Previously published catalog payload is invalid.");
  }
  if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.plugins) ||
      catalog.plugins.length > MAX_PLUGINS) {
    throw new Error("Previously published catalog schema is invalid.");
  }
  return catalog;
}

async function readLimitedBody(response, limit, label = "Release APK") {
  if (!response.body) throw new Error(`${label} response is empty.`);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new Error(`${label} exceeds size limit.`);
    }
    chunks.push(Buffer.from(value));
  }
  if (total === 0) throw new Error(`${label} response is empty.`);
  return Buffer.concat(chunks, total);
}

export function parseSignerSha256(apksignerOutput) {
  const matches = [...apksignerOutput.matchAll(
    /^\s*Signer #\d+ certificate SHA-256 digest:\s*([0-9a-f:]+)\s*$/gim,
  )];
  if (matches.length !== 1) {
    throw new Error("APK must have exactly one verifiable signing certificate.");
  }
  const digest = matches[0][1].replaceAll(":", "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error("APK signing certificate digest is invalid.");
  }
  return digest;
}

async function runApkTool(binary, args) {
  try {
    const { stdout } = await execFile(binary, args, {
      encoding: "utf8",
      windowsHide: true,
      shell: process.platform === "win32",
    });
    return stdout.trim();
  } catch (error) {
    throw new Error(`APK inspection failed (${path.basename(binary)}): ${error.message}`);
  }
}

async function inspectApk(apkBytes) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "weartak-market-"));
  const apkPath = path.join(tempDir, "release.apk");
  try {
    await writeFile(apkPath, apkBytes, { flag: "wx" });
    const packageName = await runApkTool(
      process.env.APKANALYZER || "apkanalyzer",
      ["manifest", "application-id", apkPath],
    );
    const versionCodeText = await runApkTool(
      process.env.APKANALYZER || "apkanalyzer",
      ["manifest", "version-code", apkPath],
    );
    const versionName = await runApkTool(
      process.env.APKANALYZER || "apkanalyzer",
      ["manifest", "version-name", apkPath],
    );
    const signerOutput = await runApkTool(
      process.env.APKSIGNER || "apksigner",
      ["verify", "--verbose", "--print-certs", apkPath],
    );
    const versionCode = Number(versionCodeText);
    if (!PACKAGE_PATTERN.test(packageName) || !Number.isSafeInteger(versionCode) ||
        versionCode <= 0 || !versionName) {
      throw new Error("APK package or version metadata is invalid.");
    }
    return {
      packageName,
      versionName,
      versionCode,
      signerSha256: parseSignerSha256(signerOutput),
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function validBounds(range) {
  return Number.isSafeInteger(range.minHostVersionCode) && range.minHostVersionCode > 0 &&
    (range.maxHostVersionCode === null ||
      (Number.isSafeInteger(range.maxHostVersionCode) &&
        range.maxHostVersionCode >= range.minHostVersionCode));
}

function validateCompatibility(source, schemaVersion) {
  if (schemaVersion === 1) {
    if (!validBounds(source)) {
      throw new Error(`Approved repository '${source.repo}' has invalid host-version bounds.`);
    }
    return;
  }
  const targets = source.targets;
  if (!Array.isArray(targets) || targets.length === 0 ||
      targets.some((item) => !item || typeof item !== "object" || Array.isArray(item) ||
        Object.keys(item).length !== 4 ||
        !Object.hasOwn(item, "productId") || !PRODUCT_IDS.has(item.productId) ||
        !Object.hasOwn(item, "editionIds") || !Array.isArray(item.editionIds) ||
        item.editionIds.length === 0 ||
        item.editionIds.some((id) => !EDITION_IDS.has(id)) ||
        new Set(item.editionIds).size !== item.editionIds.length ||
        !Object.hasOwn(item, "minHostVersionCode") ||
        !Object.hasOwn(item, "maxHostVersionCode") || !validBounds(item)) ||
      new Set(targets.map((item) => item.productId)).size !== targets.length ||
      ["minHostVersionCode", "maxHostVersionCode", "productIds", "editionIds", "hostVersionRanges"]
        .some((field) => Object.hasOwn(source, field))) {
    throw new Error(`Approved repository '${source.repo}' has invalid targets.`);
  }
}

function validateSource(source, target, schemaVersion) {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw new Error("Approved repository entry is invalid.");
  }
  const textLimits = {
    owner: 100,
    repo: 100,
    id: 100,
    name: 100,
    description: 1000,
    publisher: 100,
  };
  for (const [field, maxLength] of Object.entries(textLimits)) {
    if (typeof source[field] !== "string" || !source[field].trim()) {
      throw new Error(`Approved repository has invalid '${field}'.`);
    }
    if (source[field].length > maxLength) {
      throw new Error(`Approved repository '${source.repo}' has an oversized '${field}'.`);
    }
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(source.owner) ||
      !/^[A-Za-z0-9_.-]+$/.test(source.repo)) {
    throw new Error("Approved repository name is invalid.");
  }
  validateCompatibility(source, schemaVersion);
  if (!["official", "community"].includes(source.publisherType) ||
      typeof source.hostUpdate !== "boolean") {
    throw new Error(`Approved repository '${source.repo}' has invalid publisher policy.`);
  }
  if (source.hostUpdate) {
    const hostTarget = target === "shared"
      ? [...CATALOG_TARGETS.entries()].find(([, host]) =>
        host.packageName === source.packageName &&
        `${source.owner.toLowerCase()}/${source.repo.toLowerCase()}` === host.repository)?.[0]
      : target;
    const profile = hostTarget && catalogTarget(hostTarget);
    if (source.publisherType !== "official" ||
        !profile ||
        source.packageName !== profile.packageName ||
        `${source.owner.toLowerCase()}/${source.repo.toLowerCase()}` !== profile.repository ||
        (schemaVersion === 2 &&
          (source.targets.length !== 1 || source.targets[0].productId !== profile.productId))) {
      throw new Error(`Only the official ${target} repository and package may publish host updates.`);
    }
    if (hostTarget === "tracker" && !/^[0-9a-f]{64}$/.test(source.expectedSignerSha256 || "")) {
      throw new Error("Tracker host updates require an approved signer.");
    }
  } else if (source.publisherType !== "community" ||
      typeof source.packageName !== "string" ||
      !PACKAGE_PATTERN.test(source.packageName) ||
      !/^[0-9a-f]{64}$/.test(source.expectedSignerSha256 || "")) {
    throw new Error("Community entries require an approved package and signer.");
  }
  if (!source.hostUpdate &&
      [...CATALOG_TARGETS.values()].some((host) => host.packageName === source.packageName)) {
    throw new Error("Community repository cannot publish a WearTAK host package.");
  }
  if (typeof source.assetPattern !== "string" || source.assetPattern.length > 200) {
    throw new Error(`Approved repository '${source.repo}' has an invalid asset pattern.`);
  }
  try {
    new RegExp(source.assetPattern);
  } catch {
    throw new Error(`Approved repository '${source.repo}' has an invalid asset pattern.`);
  }
}

function releaseFingerprint(release, assets) {
  const releaseAssets = assets.map(({ id, name, size, updated_at, browser_download_url }) => ({
    id,
    name,
    size,
    updated_at,
    browser_download_url,
  }));
  const content = JSON.stringify({
    tagName: release.tag_name,
    publishedAt: release.published_at,
    assets: releaseAssets,
  });
  return createHash("sha256").update(content).digest("hex");
}

function matchesApprovedSource(entry, source, fingerprint, eligibleAssets, schemaVersion) {
  return entry &&
    entry.publisherReleaseFingerprint === fingerprint &&
    eligibleAssets.some((asset) => asset.browser_download_url === entry.apkUrl) &&
    entry.id === source.id &&
    entry.name === source.name &&
    entry.description === source.description &&
    entry.publisher === source.publisher &&
    entry.publisherType === source.publisherType &&
    entry.packageName === source.packageName &&
    (schemaVersion === 1
      ? entry.minHostVersionCode === source.minHostVersionCode &&
        entry.maxHostVersionCode === source.maxHostVersionCode
      : JSON.stringify(entry.targets) === JSON.stringify(source.targets)) &&
    entry.hostUpdate === source.hostUpdate &&
    (!source.expectedSignerSha256 ||
      entry.signerSha256 === source.expectedSignerSha256.toLowerCase());
}

async function inspectReleaseAssets(source, release, fetchImpl, inspect, previousEntry, schemaVersion) {
  const assetPattern = new RegExp(source.assetPattern, "i");
  const assets = (release.assets || [])
    .filter((asset) => assetPattern.test(asset.name))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (assets.length === 0) {
    throw new Error(`Approved repository '${source.repo}' has no matching APK in its latest release.`);
  }
  for (const asset of assets) {
    if (!asset.name.toLowerCase().endsWith(".apk") ||
        !Number.isSafeInteger(asset.size) || asset.size <= 0) {
      throw new Error(`Approved repository '${source.repo}' has an invalid APK asset.`);
    }
  }
  const eligibleAssets = assets.filter((asset) =>
    Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= MAX_APK_BYTES);
  if (eligibleAssets.length === 0) {
    console.warn(`Skipping '${source.repo}': matching APKs exceed the 250 MiB client limit.`);
    return null;
  }
  const fingerprint = releaseFingerprint(release, assets);
  if (matchesApprovedSource(previousEntry, source, fingerprint, eligibleAssets, schemaVersion)) {
    return { entry: previousEntry, reused: true };
  }

  const candidates = [];
  for (const asset of eligibleAssets) {
    const downloadUrl = requireHttps(asset.browser_download_url, "APK URL");
    if (downloadUrl.hostname !== "github.com" ||
        !downloadUrl.pathname.includes(`/${source.owner}/${source.repo}/releases/download/`)) {
      throw new Error(`Approved repository '${source.repo}' APK is not hosted by its GitHub release.`);
    }
    const response = await fetchHttps(
      fetchImpl,
      downloadUrl.toString(),
      "application/octet-stream",
      { githubAssetRedirects: true },
    );
    if (!response.ok) {
      throw new Error(`APK download failed for '${source.repo}' (HTTP ${response.status}).`);
    }
    const apkBytes = await readLimitedBody(response, MAX_APK_BYTES);
    const metadata = await inspect(apkBytes, asset);
    if (source.packageName && metadata.packageName !== source.packageName) {
      throw new Error(`WearTAK APK package mismatch in '${source.repo}'.`);
    }
    if (source.expectedSignerSha256 &&
        metadata.signerSha256 !== source.expectedSignerSha256.toLowerCase()) {
      throw new Error(`APK signer mismatch in approved repository '${source.repo}'.`);
    }
    candidates.push({
      asset,
      apkSha256: createHash("sha256").update(apkBytes).digest("hex"),
      metadata,
    });
  }

  candidates.sort((left, right) => right.metadata.versionCode - left.metadata.versionCode);
  if (candidates.length > 1 &&
      candidates[0].metadata.versionCode === candidates[1].metadata.versionCode &&
      candidates[0].apkSha256 !== candidates[1].apkSha256) {
    throw new Error(`Approved repository '${source.repo}' has ambiguous APKs at the same version.`);
  }
  return { ...candidates[0], fingerprint, reused: false };
}

export async function buildCatalog(config, {
  fetchImpl = globalThis.fetch,
  inspect = inspectApk,
  previousCatalog = null,
  target = "wearos",
} = {}) {
  if (target !== "shared") catalogTarget(target);
  const schemaVersion = target === "shared" ? 2 : 1;
  if (config?.schemaVersion !== schemaVersion || !Array.isArray(config.repositories) ||
      !Array.isArray(config.pendingRepositories || [])) {
    throw new Error("Approved repository configuration schema is invalid.");
  }
  if ((config.catalogTarget ?? "wearos") !== target) {
    throw new Error("Approved repository configuration does not match the catalog target.");
  }
  if (config.repositories.length > MAX_PLUGINS) {
    throw new Error("Approved repository count exceeds catalog limit.");
  }

  const ids = new Set();
  const repos = new Set();
  for (const source of config.repositories) {
    validateSource(source, target, schemaVersion);
    const fullName = `${source.owner.toLowerCase()}/${source.repo.toLowerCase()}`;
    if (ids.has(source.id) || repos.has(fullName)) {
      throw new Error("Approved repository configuration contains duplicates.");
    }
    ids.add(source.id);
    repos.add(fullName);
  }
  const pendingRepos = new Set();
  for (const repository of config.pendingRepositories || []) {
    if (typeof repository !== "string" ||
        !/^[A-Za-z0-9_.-]+\/weartak-plugin-[A-Za-z0-9_.-]+$/.test(repository)) {
      throw new Error("Pending repository list contains an invalid repository.");
    }
    const fullName = repository.toLowerCase();
    if (repos.has(fullName) || pendingRepos.has(fullName)) {
      throw new Error("Approved and pending repository lists contain duplicates.");
    }
    pendingRepos.add(fullName);
  }

  const plugins = [];
  const previousEntries = new Map(
    (previousCatalog?.schemaVersion === schemaVersion && Array.isArray(previousCatalog.plugins)
      ? previousCatalog.plugins : []).map((plugin) => [plugin.id, plugin]),
  );
  for (const source of config.repositories) {
    const apiUrl = `https://api.github.com/repos/${source.owner}/${source.repo}/releases/latest`;
    const release = await getJson(fetchImpl, apiUrl, `${source.owner}/${source.repo}`);
    if (release === null) {
      throw new Error(`Approved repository '${source.repo}' has no stable release.`);
    }
    if (release.draft || release.prerelease) continue;

    const selected = await inspectReleaseAssets(
      source,
      release,
      fetchImpl,
      inspect,
      previousEntries.get(source.id),
      schemaVersion,
    );
    if (selected === null) {
      if (source.hostUpdate && (target === "tracker" ||
          (target === "shared" &&
            source.targets.some((item) => item.productId === "weartak-tracker")))) {
        throw new Error("Tracker host APK exceeds the 250 MiB client limit; catalog was not built.");
      }
      continue;
    }
    if (selected.reused) {
      plugins.push(selected.entry);
      continue;
    }
    const assetUrl = requireHttps(selected.asset.browser_download_url, "APK URL").toString();
    plugins.push({
      id: source.id,
      name: source.name,
      description: source.description,
      publisher: source.publisher,
      publisherType: source.publisherType,
      packageName: selected.metadata.packageName,
      versionName: selected.metadata.versionName,
      versionCode: selected.metadata.versionCode,
      ...(schemaVersion === 1 ? {
        minHostVersionCode: source.minHostVersionCode,
        maxHostVersionCode: source.maxHostVersionCode,
      } : {
        targets: source.targets,
      }),
      apkUrl: assetUrl,
      apkSha256: selected.apkSha256,
      signerSha256: selected.metadata.signerSha256,
      sourceUrl: `https://github.com/${source.owner}/${source.repo}`,
      hostUpdate: source.hostUpdate,
      publisherReleaseFingerprint: selected.fingerprint,
    });
  }

  const packageNames = plugins.map((plugin) => plugin.packageName);
  if (new Set(packageNames).size !== packageNames.length) {
    throw new Error("Catalog sources contain duplicate APK package names.");
  }
  if ((target === "tracker" || (target === "shared" &&
      config.repositories.some((source) => source.hostUpdate &&
        source.targets.some((item) => item.productId === "weartak-tracker")))) &&
      !plugins.some((plugin) => plugin.hostUpdate &&
        plugin.packageName === CATALOG_TARGETS.get("tracker").packageName)) {
    throw new Error("Tracker catalog requires an eligible verified host APK.");
  }
  plugins.sort((left, right) => left.id.localeCompare(right.id));
  return { schemaVersion, plugins };
}

export function signCatalog(catalog, privateKeyPem, expectedPublicKeyBase64) {
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    throw new Error("Catalog signing key is not a valid PEM private key.");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Catalog signing key must use Ed25519.");
  }
  const publicKeyBytes = createPublicKey(privateKey)
    .export({ format: "der", type: "spki" });
  const publicKeyBase64 = Buffer.from(publicKeyBytes).toString("base64");
  if (!expectedPublicKeyBase64 || publicKeyBase64 !== expectedPublicKeyBase64.trim()) {
    throw new Error("Catalog signing key does not match configured public key.");
  }

  const payload = Buffer.from(JSON.stringify(catalog), "utf8");
  if (payload.length > MAX_CATALOG_BYTES || catalog.plugins.length > MAX_PLUGINS) {
    throw new Error("Catalog exceeds supported size or entry count.");
  }
  const signature = sign(null, payload, privateKey);
  return JSON.stringify({
    payload: payload.toString("base64"),
    signature: signature.toString("base64"),
  });
}

async function main() {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const target = process.env.MARKET_CATALOG_TARGET || "wearos";
  const profile = target === "shared" ? null : catalogTarget(target);
  const configPath = process.env.MARKET_APPROVED_REPOSITORIES ||
    (profile && path.join(currentDir, profile.configFile));
  if (!configPath) throw new Error("Shared catalog requires MARKET_APPROVED_REPOSITORIES.");
  const config = JSON.parse(await readFile(configPath, "utf8"));
  const privateKey = process.env.MARKET_CATALOG_SIGNING_KEY || "";
  const publicKey = process.env.MARKET_CATALOG_PUBLIC_KEY || "";
  signCatalog({ schemaVersion: 1, plugins: [] }, privateKey, publicKey);
  const previousCatalog = profile
    ? await fetchPreviousCatalog(globalThis.fetch, publicKey, target)
    : null;
  const catalog = await buildCatalog(config, { previousCatalog, target });
  const envelope = signCatalog(catalog, privateKey, publicKey);
  const outputDir = process.env.MARKET_OUTPUT_DIR ||
    path.join(currentDir, profile ? profile.outputDirectory : "shared-site");
  await mkdir(outputDir, { recursive: true });
  await writeFile(path.join(outputDir, "catalog.json"), envelope, { mode: 0o644 });
  console.log(`Published catalog envelope with ${catalog.plugins.length} release(s).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
