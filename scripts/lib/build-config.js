import fs from "node:fs";
import path from "node:path";

const DEFAULTS = Object.freeze({
  REPO_URL: "https://github.com/BurntToasters/centrald",
  UPDATE_BASE_URL: "",
  ARTIFACT_BASE_URL_TEMPLATE: "",
  CDN_BASE_URL: "",
  RELEASE_CHANNEL: "",
  RELEASE_MANIFEST: "centrald-release.yml",
  TAURI_UPDATE_MANIFEST: "centrald-admin-updater.json",
  TAURI_UPDATER_PUBKEY: "",
  MINISIGN_PUBLIC_KEY: "",
});

const ALLOWED_KEYS = new Set(Object.keys(DEFAULTS));
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const CHANNEL_NAME = /^(?:stable|alpha|beta)$/u;

/// The only release channels CentralD serves.
export const SUPPORTED_CHANNELS = ["stable", "alpha", "beta"];

function firstNonEmpty(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

/// Resolves the release channel. Precedence: an explicit `overrides` value,
/// then the CENTRALD_RELEASE_CHANNEL environment variable, then the tracked
/// `centrald.config`, then auto-detection from the package version (no
/// prerelease suffix = stable; otherwise the prerelease identifier, e.g.
/// `alpha` or `beta`).
export function resolveReleaseChannel(values, version, overrides = {}) {
  const explicit = firstNonEmpty(
    overrides.releaseChannel,
    process.env.CENTRALD_RELEASE_CHANNEL,
  );
  if (explicit) return explicit;
  const configured = values.RELEASE_CHANNEL.trim();
  if (configured) return configured;
  return detectChannelFromVersion(version);
}

/// Derives the channel from a SemVer version: `1.2.3` -> `stable`,
/// `1.2.3-alpha.1` -> `alpha`, `1.2.3-beta.2` -> `beta`. Any other prerelease
/// identifier is rejected because CentralD serves exactly three channels.
export function detectChannelFromVersion(version) {
  const hyphen = version.indexOf("-");
  if (hyphen === -1) return "stable";
  const prerelease = version.slice(hyphen + 1);
  const identifier = prerelease.split(".")[0].toLowerCase();
  if (!identifier) return "stable";
  if (!CHANNEL_NAME.test(identifier)) {
    throw new Error(
      `Version ${version} detects unsupported channel ${identifier}; CentralD serves exactly stable, alpha, and beta`,
    );
  }
  return identifier;
}

/// Loads the tracked build configuration. `overrides.releaseChannel` wins over
/// the CENTRALD_RELEASE_CHANNEL environment variable, which wins over the
/// tracked file, which wins over version auto-detection, so one tree can
/// produce alpha/beta/stable builds without editing centrald.config.
export function loadBuildConfig(root = process.cwd(), overrides = {}) {
  const configPath = path.join(root, "centrald.config");
  const source = fs.readFileSync(configPath, "utf8");
  const values = { ...DEFAULTS };
  const seen = new Set();

  for (const [index, rawLine] of source.split(/\r?\n/u).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) {
      throw new Error(`centrald.config:${index + 1}: expected KEY=value`);
    }
    const key = line.slice(0, separator).trim();
    if (!ALLOWED_KEYS.has(key)) {
      throw new Error(`centrald.config:${index + 1}: unknown key ${key}`);
    }
    if (seen.has(key)) {
      throw new Error(`centrald.config:${index + 1}: duplicate key ${key}`);
    }
    seen.add(key);
    values[key] = unquote(line.slice(separator + 1).trim()).replaceAll(
      "\\n",
      "\n",
    );
  }

  const repoUrl = validateHttpsBase(values.REPO_URL, "REPO_URL");
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(root, "package.json"), "utf8"),
  );
  const version = packageJson.version;
  const explicit = firstNonEmpty(
    overrides.releaseChannel,
    process.env.CENTRALD_RELEASE_CHANNEL,
  );
  const configured = values.RELEASE_CHANNEL.trim();
  const releaseChannel = resolveReleaseChannel(values, version, overrides);
  if (!CHANNEL_NAME.test(releaseChannel)) {
    throw new Error(
      `RELEASE_CHANNEL must be one of ${SUPPORTED_CHANNELS.join(", ")}`,
    );
  }
  const channelSource = explicit
    ? "override"
    : configured
      ? "configured"
      : "detected";
  const cdnBaseUrl = values.CDN_BASE_URL
    ? validateHttpsBase(values.CDN_BASE_URL, "CDN_BASE_URL")
    : "";
  const updateBaseUrl = values.UPDATE_BASE_URL
    ? validateHttpsBase(values.UPDATE_BASE_URL, "UPDATE_BASE_URL")
    : cdnBaseUrl
      ? `${cdnBaseUrl}/${releaseChannel}`
      : defaultUpdateBase(repoUrl, releaseChannel);
  const artifactBaseUrlTemplate = values.ARTIFACT_BASE_URL_TEMPLATE
    ? validateArtifactTemplate(values.ARTIFACT_BASE_URL_TEMPLATE)
    : defaultArtifactTemplate(repoUrl);

  for (const key of ["RELEASE_MANIFEST", "TAURI_UPDATE_MANIFEST"]) {
    if (!FILE_NAME.test(values[key])) {
      throw new Error(`${key} must be a simple file name`);
    }
  }

  return Object.freeze({
    repoUrl,
    updateBaseUrl,
    artifactBaseUrlTemplate,
    cdnBaseUrl,
    releaseChannel,
    channelSource,
    releaseManifest: values.RELEASE_MANIFEST,
    tauriUpdateManifest: values.TAURI_UPDATE_MANIFEST,
    tauriUpdaterPubkey: validateSingleLinePublicValue(
      values.TAURI_UPDATER_PUBKEY,
      "TAURI_UPDATER_PUBKEY",
    ),
    minisignPublicKey: validateMinisignPublicKey(values.MINISIGN_PUBLIC_KEY),
  });
}

export function releaseManifestUrl(config) {
  return `${config.updateBaseUrl}/${config.releaseManifest}`;
}

export function tauriManifestUrl(config) {
  return `${config.updateBaseUrl}/${config.tauriUpdateManifest}`;
}

export function artifactBaseUrl(config, version) {
  if (!/^[0-9A-Za-z][0-9A-Za-z.+-]*$/u.test(version)) {
    throw new Error(`Invalid release version ${JSON.stringify(version)}`);
  }
  return config.artifactBaseUrlTemplate
    .replaceAll("{version}", version)
    .replaceAll("{tag}", `v${version}`)
    .replace(/\/+$/u, "");
}

function defaultUpdateBase(repoUrl, releaseChannel) {
  if (isGitHubRepository(repoUrl)) {
    if (releaseChannel === "stable") {
      return `${repoUrl}/releases/latest/download`;
    }
    const parsed = new URL(repoUrl);
    const pieces = parsed.pathname.replace(/^\/+|\/+$/gu, "").split("/");
    if (pieces.length !== 2 || pieces.some((piece) => !piece)) {
      throw new Error("GitHub REPO_URL must contain exactly owner/repository");
    }
    const [owner, repository] = pieces;
    return `https://raw.githubusercontent.com/${owner}/${repository}/centrald-channels/channels/${releaseChannel}/latest`;
  }
  return releaseChannel === "stable"
    ? `${repoUrl}/latest`
    : `${repoUrl}/${releaseChannel}/latest`;
}

function defaultArtifactTemplate(repoUrl) {
  return isGitHubRepository(repoUrl)
    ? `${repoUrl}/releases/download/{tag}`
    : `${repoUrl}/releases/{version}`;
}

function isGitHubRepository(url) {
  const parsed = new URL(url);
  return parsed.hostname.toLowerCase() === "github.com";
}

function validateHttpsBase(value, key) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${key} must be an absolute HTTPS URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(
      `${key} must be HTTPS and cannot contain credentials, a query, or a fragment`,
    );
  }
  return parsed.toString().replace(/\/+$/u, "");
}

function validateArtifactTemplate(value) {
  if (!value.includes("{version}") && !value.includes("{tag}")) {
    throw new Error(
      "ARTIFACT_BASE_URL_TEMPLATE must contain {version} or {tag}",
    );
  }
  const substituted = value
    .replaceAll("{version}", "1.2.3")
    .replaceAll("{tag}", "v1.2.3");
  validateHttpsBase(substituted, "ARTIFACT_BASE_URL_TEMPLATE");
  return value.replace(/\/+$/u, "");
}

function validateSingleLinePublicValue(value, key) {
  if (/[\r\n\0]/u.test(value)) {
    throw new Error(`${key} must be a single-line public value`);
  }
  return value.trim();
}

function validateMinisignPublicKey(value) {
  const key = validateSingleLinePublicValue(value, "MINISIGN_PUBLIC_KEY");
  if (key && !/^RW[A-Za-z0-9+/=]+$/u.test(key)) {
    throw new Error(
      "MINISIGN_PUBLIC_KEY must be the base64 public key beginning with RW",
    );
  }
  return key;
}

function unquote(value) {
  if (value.length >= 2) {
    const first = value.at(0);
    const last = value.at(-1);
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return value.slice(1, -1);
    }
  }
  return value;
}
