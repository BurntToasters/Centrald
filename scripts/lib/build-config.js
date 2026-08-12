import fs from "node:fs";
import path from "node:path";

const DEFAULTS = Object.freeze({
  REPO_URL: "https://github.com/BurntToasters/centrald",
  UPDATE_BASE_URL: "",
  ARTIFACT_BASE_URL_TEMPLATE: "",
  RELEASE_CHANNEL: "stable",
  RELEASE_MANIFEST: "centrald-release.yml",
  TAURI_UPDATE_MANIFEST: "centrald-admin-updater.json",
  TAURI_UPDATER_PUBKEY: "",
  MINISIGN_PUBLIC_KEY: "",
});

const ALLOWED_KEYS = new Set(Object.keys(DEFAULTS));
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function loadBuildConfig(root = process.cwd()) {
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
  if (!/^[a-z0-9][a-z0-9._-]{0,31}$/u.test(values.RELEASE_CHANNEL)) {
    throw new Error("RELEASE_CHANNEL must be a lowercase channel name");
  }
  const updateBaseUrl = values.UPDATE_BASE_URL
    ? validateHttpsBase(values.UPDATE_BASE_URL, "UPDATE_BASE_URL")
    : defaultUpdateBase(repoUrl, values.RELEASE_CHANNEL);
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
    releaseChannel: values.RELEASE_CHANNEL,
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
