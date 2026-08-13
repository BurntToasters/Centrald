import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { commandExists, run } from "./command.js";
import { loadBuildConfig } from "./lib/build-config.js";
import { compareSemver } from "./lib/release-metadata.js";
import {
  cleanGeneratedDirectory,
  ensureGeneratedDirectory,
} from "./lib/safe-path.js";

const root = process.cwd();
const action = process.argv[2];
const supported = new Set([
  "prepare",
  "build",
  "assemble",
  "sign",
  "manifests",
  "verify",
  "publish",
  "publish-channel",
  "all",
]);
if (!supported.has(action)) {
  throw new Error(`Unknown release action: ${action}`);
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const version = packageJson.version;
const config = loadBuildConfig(root);

if (action === "prepare") prepare();
if (action === "build") buildAllPlatforms();
if (action === "assemble") assembleArtifacts();
if (action === "sign") signReleaseArtifacts();
if (action === "manifests") generateManifests();
if (action === "verify") verify();
if (action === "publish") publish();
if (action === "publish-channel") publishChannelOnly();
if (action === "all") {
  prepare();
  buildAllPlatforms();
  assembleArtifacts();
  // Artifacts are signed before manifest generation so every described
  // artifact has a signature_url. Manifests are generated from the signed
  // artifact set and then signed again so their own .minisig files exist for
  // the release upload.
  signReleaseArtifacts();
  generateManifests();
  signReleaseArtifacts();
  if (process.env.CENTRALD_RELEASE_PUBLISH === "YES") {
    requirePublishEnvironment();
    createAndPushVersionTag();
    // publish() runs its own full verification before uploading.
    publish();
  } else {
    verify();
    console.log(
      "Release artifacts are built and verified. Publishing was skipped: set CENTRALD_RELEASE_PUBLISH=YES in .env to create the version tag and publish.",
    );
  }
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

function prepare() {
  requireCleanTree();
  verifyVersionSync();
  verifyOrigin();
  refreshHostRustStable();
  ensureGeneratedDirectory(root, "release");
  console.log(`Release preflight passed for v${version}.`);
}

/// The project always builds on the latest stable Rust. Refresh the host
/// toolchain so a native build (or rustup-driven step) matches what the
/// container images provide; container images run their own rustup update.
function refreshHostRustStable() {
  if (!commandExists("rustup", ["--version"])) {
    console.log(
      "Host rustup is not installed; container builds supply their own latest-stable Rust toolchain.",
    );
    return;
  }
  run("rustup", ["update", "stable"]);
  console.log("Host Rust stable toolchain is up to date.");
}

function requireCleanTree() {
  if (git(["status", "--porcelain=v1", "--untracked-files=all"])) {
    throw new Error("Release operations require a clean working tree.");
  }
}

function verifyVersionSync() {
  const cargo = fs.readFileSync(path.join(root, "Cargo.toml"), "utf8");
  if (!cargo.includes(`version = "${version}"`)) {
    throw new Error("Cargo workspace and package.json versions differ.");
  }
  const tauri = JSON.parse(
    fs.readFileSync(
      path.join(root, "apps/admin/src-tauri/tauri.conf.json"),
      "utf8",
    ),
  );
  if (tauri.version !== version) {
    throw new Error("Tauri and package.json versions differ.");
  }
}

function verifyOrigin() {
  const remote = git(["remote", "get-url", "origin"]);
  const normalizedRemote = normalizeRepository(remote);
  const normalizedConfigured = normalizeRepository(config.repoUrl);
  if (normalizedRemote !== normalizedConfigured) {
    throw new Error(
      `origin resolves to ${normalizedRemote}; centrald.config expects ${normalizedConfigured}.`,
    );
  }
}

function normalizeRepository(value) {
  let normalized = value.trim().replace(/\.git$/u, "");
  const scp = /^git@([^:]+):(.+)$/u.exec(normalized);
  if (scp) normalized = `https://${scp[1]}/${scp[2]}`;
  const ssh = /^ssh:\/\/git@([^/]+)\/(.+)$/u.exec(normalized);
  if (ssh) normalized = `https://${ssh[1]}/${ssh[2]}`;
  return normalized.replace(/\/+$/u, "").toLowerCase();
}

function buildAllPlatforms() {
  prepare();
  const signed = Boolean(process.env.TAURI_SIGNING_PRIVATE_KEY);
  const signingArguments = signed ? ["--signed"] : [];
  if (process.platform === "win32") {
    // A Windows host builds every platform inside Docker containers (Linux
    // engine for Linux artifacts, Windows engine for Windows artifacts), so
    // build issues stay isolated from the machine. The Docker-built Linux
    // AppImage and Windows NSIS installers are Tauri-signed on the host
    // afterwards (build.js), keeping signing keys out of Docker build
    // arguments.
    run("node", [
      "scripts/build.js",
      "--target",
      "all",
      "--container",
      ...signingArguments,
    ]);
  } else if (process.platform === "linux") {
    run("node", [
      "scripts/build.js",
      "--target",
      "linux-x64",
      "--native",
      ...signingArguments,
    ]);
  } else {
    throw new Error("CentralD release builds support only Windows and Linux.");
  }
}

function assembleArtifacts() {
  verifyVersionSync();
  cleanGeneratedDirectory(root, "release/artifacts");
  const destination = ensureGeneratedDirectory(root, "release/artifacts");
  const roots = ["dist/linux-x64", "dist/windows-x64", "dist/windows-arm64"];
  let copied = 0;
  for (const relative of roots) {
    const directory = path.join(root, relative);
    if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) {
      continue;
    }
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isFile() || entry.name === ".centrald-generated") continue;
      if (!entry.name.startsWith("centrald-")) continue;
      const source = path.join(directory, entry.name);
      const target = path.join(destination, entry.name);
      if (fs.existsSync(target)) {
        throw new Error(`Duplicate release artifact ${entry.name}`);
      }
      if (fs.lstatSync(source).isSymbolicLink()) {
        throw new Error(`Refusing symbolic-link release artifact ${source}`);
      }
      fs.copyFileSync(source, target, fs.constants.COPYFILE_EXCL);
      copied += 1;
    }
  }
  if (copied === 0) {
    throw new Error("No built CentralD artifacts were found under dist/.");
  }
  console.log(`Assembled ${copied} files in ${destination}.`);
}

function generateManifests() {
  verifyVersionSync();
  run(
    "node",
    [
      "scripts/generate-manifests.js",
      "--artifacts-dir",
      "release/artifacts",
      "--output-dir",
      "release",
      "--require-complete",
      "--require-release-signatures",
      "--require-signatures",
    ],
    { env: releaseManifestEnvironment() },
  );
}

function signReleaseArtifacts() {
  verifyVersionSync();
  const args = ["scripts/sign-release.js"];
  if (process.env.CENTRALD_MINISIGN_UNPROTECTED_KEY === "YES") {
    args.push("--unprotected-key");
  }
  run("node", args);
}

function verify() {
  requireCleanTree();
  verifyVersionSync();
  verifyOrigin();
  run("npm", ["run", "qa"]);
  requireRegularFile(path.join(root, "release", config.releaseManifest));
  requireRegularFile(path.join(root, "release", config.tauriUpdateManifest));
  run(
    "node",
    [
      "scripts/generate-manifests.js",
      "--artifacts-dir",
      "release/artifacts",
      "--output-dir",
      "release",
      "--require-complete",
      "--require-release-signatures",
      "--require-signatures",
    ],
    { env: releaseManifestEnvironment() },
  );
  console.log("Release verification passed.");
}

function publish() {
  verify();
  requirePublishEnvironment();
  const expectedTag = requireExactVersionTag();
  publishImmutableVersionRelease(expectedTag, releaseFiles(true));

  if (config.releaseChannel !== "stable") {
    publishMutableChannelManifests(config.releaseChannel);
  }
  console.log(`Published CentralD v${version}.`);
}

function publishChannelOnly() {
  requireCleanTree();
  verifyVersionSync();
  verifyOrigin();
  run("npm", ["run", "qa"]);
  requirePublishEnvironment();
  const expectedTag = requireExactVersionTag();
  if (config.releaseChannel === "stable") {
    throw new Error(
      "Stable updates are served by the immutable latest version release; there is no mutable stable channel branch to publish.",
    );
  }
  const entries = immutableReleaseChannelEntries(
    expectedTag,
    config.releaseChannel,
  );
  publishMutableChannelManifests(config.releaseChannel, entries);
  console.log(
    `Published CentralD ${config.releaseChannel} channel manifests for v${version}.`,
  );
}

function requirePublishEnvironment() {
  if (process.env.CENTRALD_RELEASE_PUBLISH !== "YES") {
    throw new Error(
      "Publishing requires the exact environment variable CENTRALD_RELEASE_PUBLISH=YES.",
    );
  }
  if (process.env.CENTRALD_GITHUB_IMMUTABLE_RELEASES !== "YES") {
    throw new Error(
      "Publishing requires CENTRALD_GITHUB_IMMUTABLE_RELEASES=YES after repository release immutability has been enabled in GitHub settings.",
    );
  }
  if (!commandExists("gh")) {
    throw new Error("GitHub CLI (gh) is required for publishing.");
  }
}

function requireExactVersionTag() {
  const expectedTag = `v${version}`;
  const currentTag = git(["describe", "--tags", "--exact-match"]);
  if (currentTag !== expectedTag) {
    throw new Error(`Publish must run from exact tag ${expectedTag}.`);
  }
  return expectedTag;
}

/// Creates the `v<version>` tag at HEAD when missing and pushes it to origin,
/// refusing to move an existing tag. Publishing then runs from that tag.
function createAndPushVersionTag() {
  requireCleanTree();
  verifyVersionSync();
  verifyOrigin();
  const expectedTag = `v${version}`;
  const head = git(["rev-parse", "HEAD"]);
  if (
    spawnSucceeded("git", [
      "rev-parse",
      "-q",
      "--verify",
      `refs/tags/${expectedTag}`,
    ])
  ) {
    const local = git(["rev-list", "-n", "1", expectedTag]);
    if (local !== head) {
      throw new Error(
        `Local tag ${expectedTag} points at ${local}, not HEAD; refusing to move it.`,
      );
    }
  } else {
    run("git", ["tag", expectedTag]);
  }
  const remote = git(["ls-remote", "--tags", "origin", expectedTag]).trim();
  if (remote) {
    const remoteSha = remote.split(/\s+/u)[0];
    if (remoteSha !== head) {
      throw new Error(
        `Remote tag ${expectedTag} points at ${remoteSha}, not HEAD; refusing to move it.`,
      );
    }
    console.log(`Version tag ${expectedTag} already exists on origin.`);
  } else {
    run("git", ["push", "origin", expectedTag]);
    console.log(`Created and pushed version tag ${expectedTag}.`);
  }
}

function publishImmutableVersionRelease(tag, files) {
  if (spawnSucceeded("gh", ["release", "view", tag])) {
    verifyPublishedVersionRelease(tag, files);
    console.log(
      `Immutable version release ${tag} already exists and matches the local verified asset set.`,
    );
    return;
  }
  const args = [
    "release",
    "create",
    tag,
    "--draft",
    "--verify-tag",
    "--title",
    `CentralD ${tag}`,
    "--notes",
    `CentralD ${tag}`,
  ];
  if (version.includes("-")) args.push("--prerelease");
  run("gh", args);
  try {
    // No --clobber: each immutable asset name is accepted exactly once.
    run("gh", ["release", "upload", tag, ...files]);
    verifyDraftAssets(tag, files);
    run("gh", ["release", "edit", tag, "--draft=false"]);
  } catch (error) {
    throw new Error(
      `Version release ${tag} remains a draft after a failed publish. Inspect or delete that draft before retrying: ${error.message}`,
      { cause: error },
    );
  }
}

function verifyPublishedVersionRelease(tag, files) {
  const repository = githubRepositorySlug(config.repoUrl);
  const release = ghApiJson("GET", `repos/${repository}/releases/tags/${tag}`);
  if (release.draft) {
    throw new Error(
      `Version release ${tag} exists only as a draft; finish or delete the draft before retrying channel publication.`,
    );
  }
  verifyReleaseAssetIntegrity(release, files, `Published release ${tag}`);
}

function verifyDraftAssets(tag, files) {
  const repository = githubRepositorySlug(config.repoUrl);
  const release = ghApiJson("GET", `repos/${repository}/releases/tags/${tag}`);
  if (!release.draft) {
    throw new Error(
      `Version release ${tag} is not a draft during publication.`,
    );
  }
  verifyReleaseAssetIntegrity(release, files, `Draft release ${tag}`);
}

function verifyReleaseAssetIntegrity(release, files, label) {
  const expected = files
    .map((file) => ({
      name: path.basename(file),
      size: fs.statSync(file).size,
      digest: `sha256:${sha256File(file)}`,
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
  const actual = (release.assets ?? [])
    .map((asset) => ({
      name: asset.name,
      size: asset.size,
      digest: asset.digest ?? "",
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `${label} assets do not match the locally verified names, sizes, and SHA-256 digests.`,
    );
  }
}

function sha256File(file) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(file))
    .digest("hex");
}

function publishMutableChannelManifests(channel, suppliedEntries) {
  const repository = githubRepositorySlug(config.repoUrl);
  const branch = "centrald-channels";
  const entries = suppliedEntries ?? localChannelEntries(channel);

  ensureChannelBranch(repository, branch);
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      publishChannelTree(repository, branch, channel, entries);
      return;
    } catch (error) {
      lastError = error;
      if (error?.code !== "CENTRALD_CHANNEL_REF_CONFLICT" || attempt === 3) {
        throw error;
      }
    }
  }
  throw new Error(
    `Could not atomically publish ${channel} channel manifests after three concurrent branch updates: ${lastError?.message ?? "unknown error"}`,
    { cause: lastError },
  );
}

function publishChannelTree(repository, branch, channel, entries) {
  const head = ghApiJson("GET", `repos/${repository}/git/ref/heads/${branch}`);
  const parentSha = head.object?.sha;
  if (!parentSha) throw new Error(`Could not resolve ${branch} branch head.`);
  const parent = ghApiJson(
    "GET",
    `repos/${repository}/git/commits/${parentSha}`,
  );
  const baseTree = parent.tree?.sha;
  if (!baseTree) throw new Error(`Could not resolve ${branch} base tree.`);

  const existing = currentChannelEntries(repository, baseTree, entries);
  const advance = validateChannelAdvance(channel, existing, entries);
  if (advance === "unchanged") {
    console.log(`CentralD ${channel} channel already points to v${version}.`);
    return;
  }

  const treeEntries = entries.map(({ content, remotePath }) => {
    const blob = ghApiJson("POST", `repos/${repository}/git/blobs`, {
      content: content.toString("base64"),
      encoding: "base64",
    });
    if (!blob.sha)
      throw new Error(`GitHub did not return a blob SHA for ${remotePath}.`);
    return { path: remotePath, mode: "100644", type: "blob", sha: blob.sha };
  });

  const tree = ghApiJson("POST", `repos/${repository}/git/trees`, {
    base_tree: baseTree,
    tree: treeEntries,
  });
  if (!tree.sha) throw new Error("GitHub did not return a channel tree SHA.");
  const commit = ghApiJson("POST", `repos/${repository}/git/commits`, {
    message: `Update CentralD ${channel} channel manifests for v${version}`,
    tree: tree.sha,
    parents: [parentSha],
  });
  if (!commit.sha)
    throw new Error("GitHub did not return a channel commit SHA.");

  // A non-forced ref update is a compare-and-swap: if another publisher moved
  // the branch after parentSha was read, this commit is no longer a fast-forward
  // and GitHub rejects the update. The caller then rebuilds from the new head.
  try {
    ghApiJson("PATCH", `repos/${repository}/git/refs/heads/${branch}`, {
      sha: commit.sha,
      force: false,
    });
  } catch (error) {
    const latest = ghApiJson(
      "GET",
      `repos/${repository}/git/ref/heads/${branch}`,
    );
    if (latest.object?.sha !== parentSha) {
      error.code = "CENTRALD_CHANNEL_REF_CONFLICT";
    }
    throw error;
  }
}

function localChannelEntries(channel) {
  return [config.releaseManifest, config.tauriUpdateManifest].flatMap(
    (file) => {
      const localPath = path.join(root, "release", file);
      requireRegularFile(localPath);
      const signaturePath = `${localPath}.minisig`;
      requireRegularFile(signaturePath);
      const entries = [
        {
          content: fs.readFileSync(localPath),
          remotePath: `channels/${channel}/latest/${file}`,
        },
        {
          content: fs.readFileSync(signaturePath),
          remotePath: `channels/${channel}/latest/${file}.minisig`,
        },
      ];
      return entries;
    },
  );
}

function immutableReleaseChannelEntries(tag, channel) {
  const repository = githubRepositorySlug(config.repoUrl);
  const release = ghApiJson("GET", `repos/${repository}/releases/tags/${tag}`);
  if (release.draft) {
    throw new Error(
      `Version release ${tag} is still a draft; publish it before updating a channel.`,
    );
  }
  const requested = [config.releaseManifest, config.tauriUpdateManifest];
  const entries = requested.flatMap((name) => {
    const matches = (release.assets ?? []).filter(
      (asset) => asset.name === name,
    );
    if (matches.length !== 1) {
      throw new Error(
        `Immutable version release ${tag} must contain exactly one ${name} asset.`,
      );
    }
    const asset = matches[0];
    const content = downloadReleaseAsset(repository, asset);
    return [
      { content, remotePath: `channels/${channel}/latest/${name}` },
      {
        content: downloadReleaseAsset(
          repository,
          findImmutableSignatureAsset(release, name),
        ),
        remotePath: `channels/${channel}/latest/${name}.minisig`,
      },
    ];
  });
  validateImmutableReleaseManifests(release, entries, channel);
  return entries;
}

function findImmutableSignatureAsset(release, name) {
  const matches = (release.assets ?? []).filter(
    (asset) => asset.name === `${name}.minisig`,
  );
  if (matches.length !== 1) {
    throw new Error(
      `Immutable version release must contain exactly one ${name}.minisig asset.`,
    );
  }
  return matches[0];
}

function downloadReleaseAsset(repository, asset) {
  const maximum = 2 * 1024 * 1024;
  if (
    !Number.isSafeInteger(asset.id) ||
    asset.id < 1 ||
    !Number.isSafeInteger(asset.size) ||
    asset.size < 1 ||
    asset.size > maximum
  ) {
    throw new Error(
      `Release asset ${asset.name} has an invalid or excessive size.`,
    );
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(asset.digest ?? "")) {
    throw new Error(
      `Release asset ${asset.name} has no trustworthy SHA-256 digest.`,
    );
  }
  const content = execFileSync(
    "gh",
    [
      "api",
      "--header",
      "Accept: application/octet-stream",
      `repos/${repository}/releases/assets/${asset.id}`,
    ],
    { maxBuffer: maximum + 1 },
  );
  if (content.length !== asset.size) {
    throw new Error(
      `Downloaded release asset ${asset.name} has the wrong size.`,
    );
  }
  const digest = `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`;
  if (digest !== asset.digest) {
    throw new Error(
      `Downloaded release asset ${asset.name} failed SHA-256 verification.`,
    );
  }
  return content;
}

function validateImmutableReleaseManifests(release, entries, channel) {
  const sharedEntry = entries.find((entry) =>
    entry.remotePath.endsWith(`/${config.releaseManifest}`),
  );
  const updaterEntry = entries.find((entry) =>
    entry.remotePath.endsWith(`/${config.tauriUpdateManifest}`),
  );
  const shared = parseManifestJson(
    sharedEntry?.content,
    config.releaseManifest,
  );
  const updater = parseManifestJson(
    updaterEntry?.content,
    config.tauriUpdateManifest,
  );
  if (
    shared.schema_version !== 1 ||
    shared.version !== version ||
    shared.channel !== channel ||
    shared.repository !== config.repoUrl ||
    updater.version !== version
  ) {
    throw new Error(
      `Immutable version release manifests do not describe CentralD v${version} on channel ${channel}.`,
    );
  }
  const assets = new Map(
    (release.assets ?? []).map((asset) => [asset.name, asset]),
  );
  const updaterUrls = new Set();
  for (const [platform, descriptor] of Object.entries(
    updater.platforms ?? {},
  )) {
    if (
      typeof descriptor?.url !== "string" ||
      typeof descriptor?.signature !== "string" ||
      descriptor.signature.length === 0
    ) {
      throw new Error(
        `Immutable updater manifest has an invalid ${platform} entry.`,
      );
    }
    updaterUrls.add(descriptor.url);
  }
  for (const expectedPlatform of [
    "linux-x86_64",
    "windows-x86_64",
    "windows-aarch64",
  ]) {
    if (!Object.hasOwn(updater.platforms ?? {}, expectedPlatform)) {
      throw new Error(
        `Immutable updater manifest is missing ${expectedPlatform}.`,
      );
    }
  }
  let describedArtifacts = 0;
  for (const artifact of shared.artifacts ?? []) {
    describedArtifacts += 1;
    const asset = assets.get(artifact.filename);
    if (
      !asset ||
      asset.size !== artifact.size ||
      asset.digest !== `sha256:${artifact.sha256}`
    ) {
      throw new Error(
        `Immutable release artifact ${artifact.filename} does not match the shared manifest.`,
      );
    }
    if (artifact.signature_url) {
      const signatureName = new URL(artifact.signature_url).pathname
        .split("/")
        .at(-1);
      if (!signatureName || !assets.has(signatureName)) {
        throw new Error(
          `Immutable release is missing signature asset for ${artifact.filename}.`,
        );
      }
    }
    if (
      artifact.component === "admin" &&
      ["appimage", "nsis"].includes(artifact.package)
    ) {
      updaterUrls.delete(artifact.url);
    }
  }
  if (describedArtifacts === 0) {
    throw new Error("Immutable shared release manifest contains no artifacts.");
  }
  if (updaterUrls.size !== 0) {
    throw new Error(
      "Immutable updater manifest references an artifact outside the shared manifest.",
    );
  }
}

function currentChannelEntries(repository, baseTree, entries) {
  const tree = ghApiJson(
    "GET",
    `repos/${repository}/git/trees/${baseTree}?recursive=1`,
  );
  if (tree.truncated) {
    throw new Error(
      "GitHub truncated the channel branch tree; refusing to infer channel state from an incomplete response.",
    );
  }
  const files = new Map(
    (tree.tree ?? [])
      .filter((entry) => entry.type === "blob")
      .map((entry) => [entry.path, entry.sha]),
  );
  return entries.map(({ remotePath }) => {
    const sha = files.get(remotePath);
    if (!sha) return { remotePath, content: null };
    const blob = ghApiJson("GET", `repos/${repository}/git/blobs/${sha}`);
    if (blob.encoding !== "base64" || typeof blob.content !== "string") {
      throw new Error(
        `GitHub returned an unsupported blob encoding for ${remotePath}.`,
      );
    }
    return {
      remotePath,
      content: Buffer.from(blob.content.replaceAll("\n", ""), "base64"),
    };
  });
}

function validateChannelAdvance(channel, existing, next) {
  const existingPresent = existing.filter((entry) => entry.content !== null);
  if (existingPresent.length === 0) return "advance";
  if (existingPresent.length !== existing.length) {
    throw new Error(
      `Existing ${channel} channel is incomplete; repair it manually before publishing.`,
    );
  }
  const currentShared = parseManifestJson(
    existing.find((entry) =>
      entry.remotePath.endsWith(`/${config.releaseManifest}`),
    )?.content,
    `current ${config.releaseManifest}`,
  );
  const currentUpdater = parseManifestJson(
    existing.find((entry) =>
      entry.remotePath.endsWith(`/${config.tauriUpdateManifest}`),
    )?.content,
    `current ${config.tauriUpdateManifest}`,
  );
  const nextShared = parseManifestJson(
    next.find((entry) =>
      entry.remotePath.endsWith(`/${config.releaseManifest}`),
    )?.content,
    config.releaseManifest,
  );
  const nextUpdater = parseManifestJson(
    next.find((entry) =>
      entry.remotePath.endsWith(`/${config.tauriUpdateManifest}`),
    )?.content,
    config.tauriUpdateManifest,
  );
  if (currentShared.version !== currentUpdater.version) {
    throw new Error(
      `Existing ${channel} channel manifests disagree about their version.`,
    );
  }
  if (
    currentShared.channel !== channel ||
    currentShared.repository !== config.repoUrl
  ) {
    throw new Error(
      `Existing ${channel} channel manifest belongs to another channel or repository.`,
    );
  }
  if (
    nextShared.version !== nextUpdater.version ||
    nextShared.version !== version
  ) {
    throw new Error(
      `New ${channel} channel manifests disagree about their version.`,
    );
  }
  if (
    nextShared.channel !== channel ||
    nextShared.repository !== config.repoUrl
  ) {
    throw new Error(
      `New ${channel} channel manifest belongs to another channel or repository.`,
    );
  }
  const precedence = compareSemver(nextShared.version, currentShared.version);
  if (precedence < 0 && process.env.CENTRALD_ALLOW_CHANNEL_ROLLBACK !== "YES") {
    throw new Error(
      `Refusing to move ${channel} channel backward from v${currentShared.version} to v${nextShared.version}; set CENTRALD_ALLOW_CHANNEL_ROLLBACK=YES only for a deliberate emergency rollback.`,
    );
  }
  if (precedence === 0) {
    const unchanged = next.every((entry) => {
      const current = existing.find(
        (candidate) => candidate.remotePath === entry.remotePath,
      );
      return current?.content?.equals(entry.content) === true;
    });
    if (unchanged) return "unchanged";
    throw new Error(
      `Refusing to replace ${channel} channel bytes without a version change.`,
    );
  }
  return "advance";
}

function parseManifestJson(content, label) {
  if (
    !Buffer.isBuffer(content) ||
    content.length === 0 ||
    content.length > 2 * 1024 * 1024
  ) {
    throw new Error(`${label} is missing, empty, or too large.`);
  }
  try {
    return JSON.parse(content.toString("utf8"));
  } catch (error) {
    throw new Error(
      `${label} is not valid JSON-compatible YAML: ${error.message}`,
      { cause: error },
    );
  }
}

function releaseManifestEnvironment() {
  const timestamp =
    process.env.CENTRALD_RELEASE_TIMESTAMP ??
    git(["show", "-s", "--format=%cI", "HEAD"]);
  return { ...process.env, CENTRALD_RELEASE_TIMESTAMP: timestamp };
}

function ghApiJson(method, apiPath, body) {
  const args = ["api"];
  if (method !== "GET") args.push("--method", method, "--input", "-");
  args.push(apiPath);
  const options = { encoding: "utf8" };
  if (method !== "GET") options.input = `${JSON.stringify(body)}\n`;
  return JSON.parse(execFileSync("gh", args, options));
}

function ensureChannelBranch(repository, branch) {
  if (
    spawnSucceeded("gh", ["api", `repos/${repository}/git/ref/heads/${branch}`])
  ) {
    return;
  }
  const commit = git(["rev-parse", "HEAD"]);
  try {
    ghApiJson("POST", `repos/${repository}/git/refs`, {
      ref: `refs/heads/${branch}`,
      sha: commit,
    });
  } catch (error) {
    // Another publisher may have created the branch after our existence check.
    if (
      !spawnSucceeded("gh", [
        "api",
        `repos/${repository}/git/ref/heads/${branch}`,
      ])
    ) {
      throw error;
    }
  }
}

function githubRepositorySlug(repoUrl) {
  const parsed = new URL(repoUrl);
  if (parsed.hostname.toLowerCase() !== "github.com") {
    throw new Error(
      "Automatic channel publication is supported only for GitHub REPO_URL values; configure UPDATE_BASE_URL and publish manifests with your object-storage deployment for generic origins.",
    );
  }
  const pieces = parsed.pathname
    .replace(/^\/+|\/+$/gu, "")
    .replace(/\.git$/u, "")
    .split("/");
  if (pieces.length !== 2 || pieces.some((piece) => !piece)) {
    throw new Error("GitHub REPO_URL must contain exactly owner/repository");
  }
  return `${pieces[0]}/${pieces[1]}`;
}

function spawnSucceeded(command, args) {
  try {
    execFileSync(command, args, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function releaseFiles(includeArtifacts) {
  const files = [
    path.join("release", config.releaseManifest),
    path.join("release", config.releaseManifest + ".minisig"),
    path.join("release", config.tauriUpdateManifest),
    path.join("release", config.tauriUpdateManifest + ".minisig"),
  ];
  if (includeArtifacts) {
    for (const entry of fs.readdirSync(path.join(root, "release/artifacts"), {
      withFileTypes: true,
    })) {
      if (entry.isFile() && entry.name !== ".centrald-generated") {
        files.push(path.join("release/artifacts", entry.name));
      }
    }
  }
  return files;
}

function requireRegularFile(file) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`Missing release file ${file}`);
  }
  if (fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(`Refusing symbolic-link release file ${file}`);
  }
  return file;
}
