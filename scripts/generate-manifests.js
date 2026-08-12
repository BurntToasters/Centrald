import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { artifactBaseUrl, loadBuildConfig } from "./lib/build-config.js";
import { releaseTimestamp } from "./lib/release-metadata.js";
import { ensureGeneratedDirectory } from "./lib/safe-path.js";

const root = process.cwd();
const options = parseArguments(process.argv.slice(2));
const config = loadBuildConfig(root);
const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const version = packageJson.version;
const artifactsDir = path.resolve(root, options.artifactsDir);
const outputDir = path.resolve(root, options.outputDir);
const expectedOutput = path.relative(root, outputDir).replaceAll("\\", "/");
ensureGeneratedDirectory(root, expectedOutput);

if (!fs.existsSync(artifactsDir) || !fs.statSync(artifactsDir).isDirectory()) {
  throw new Error(`Artifact directory does not exist: ${artifactsDir}`);
}

const files = walk(artifactsDir);
const artifacts = files
  .map((file) => describeArtifact(file, version, config))
  .filter((artifact) => artifact !== null)
  .sort((left, right) => left.filename.localeCompare(right.filename));

if (artifacts.length === 0) {
  throw new Error(`No canonical CentralD artifacts found in ${artifactsDir}`);
}
if (options.requireComplete) validateCompleteness(artifacts);
if (options.requireReleaseSignatures) validateReleaseSignatures(artifacts);

const generatedAt = releaseTimestamp();
const releaseManifest = renderReleaseManifest({
  artifacts,
  channel: config.releaseChannel,
  generatedAt,
  protocolMajor: readProtocolMajor(root),
  repoUrl: config.repoUrl,
  version,
});
writeAtomic(path.join(outputDir, config.releaseManifest), releaseManifest);

const updater = buildTauriManifest({
  artifacts,
  generatedAt,
  notes: options.notes,
  requireSignatures: options.requireSignatures,
  version,
});
writeAtomic(
  path.join(outputDir, config.tauriUpdateManifest),
  `${JSON.stringify(updater, null, 2)}\n`,
);

console.log(`Generated ${path.join(outputDir, config.releaseManifest)}`);
console.log(`Generated ${path.join(outputDir, config.tauriUpdateManifest)}`);

function parseArguments(args) {
  const result = {
    artifactsDir: "release/artifacts",
    outputDir: "release",
    notes: process.env.CENTRALD_RELEASE_NOTES ?? "CentralD release",
    requireComplete: false,
    requireReleaseSignatures: false,
    requireSignatures: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--artifacts-dir") {
      result.artifactsDir = requiredValue(args, ++index, argument);
    } else if (argument === "--output-dir") {
      result.outputDir = requiredValue(args, ++index, argument);
    } else if (argument === "--notes") {
      result.notes = requiredValue(args, ++index, argument);
    } else if (argument === "--require-complete") {
      result.requireComplete = true;
    } else if (argument === "--require-release-signatures") {
      result.requireReleaseSignatures = true;
    } else if (argument === "--require-signatures") {
      result.requireSignatures = true;
    } else {
      throw new Error(`Unknown argument ${argument}`);
    }
  }
  return result;
}

function requiredValue(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function walk(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(absolute));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

function describeArtifact(file, expectedVersion, buildConfig) {
  if (
    file.endsWith(".sig") ||
    file.endsWith(".minisig") ||
    file.endsWith(".sha256")
  ) {
    return null;
  }
  const filename = path.basename(file);
  const match = /^centrald-(server|client|admin)_(.+)_(linux|windows)_(x86_64|aarch64)\.(deb|msi|exe|AppImage|zip|tar\.gz)$/u.exec(
    filename,
  );
  if (!match) return null;
  const [, component, version, os, architecture, extension] = match;
  if (version !== expectedVersion) {
    throw new Error(
      `${filename} has version ${version}; expected ${expectedVersion}`,
    );
  }
  if (component === "server" && os !== "linux") {
    throw new Error(`CentralD server artifacts must target Linux: ${filename}`);
  }
  const bytes = fs.readFileSync(file);
  const tauriSignaturePath = `${file}.sig`;
  const releaseSignaturePath = `${file}.minisig`;
  return {
    component,
    os,
    architecture,
    package: packageKind(extension),
    filename,
    url: `${artifactBaseUrl(buildConfig, expectedVersion)}/${filename}`,
    size: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    tauriSignature: fs.existsSync(tauriSignaturePath)
      ? fs.readFileSync(tauriSignaturePath, "utf8").trim()
      : null,
    releaseSignatureUrl: fs.existsSync(releaseSignaturePath)
      ? `${artifactBaseUrl(buildConfig, expectedVersion)}/${filename}.minisig`
      : null,
  };
}

function packageKind(extension) {
  return {
    deb: "deb",
    msi: "msi",
    exe: "nsis",
    AppImage: "appimage",
    zip: "zip",
    "tar.gz": "tar_gz",
  }[extension];
}

function readProtocolMajor(projectRoot) {
  const source = fs.readFileSync(
    path.join(projectRoot, "crates/centrald-protocol/src/lib.rs"),
    "utf8",
  );
  const match = /pub const PROTOCOL_MAJOR: u32 = (\d+);/u.exec(source);
  if (!match) throw new Error("Could not read PROTOCOL_MAJOR");
  return Number(match[1]);
}

function renderReleaseManifest({
  artifacts,
  channel,
  generatedAt,
  protocolMajor,
  repoUrl,
  version,
}) {
  // JSON is a strict subset of YAML 1.2. Keeping the tracked .yml filename
  // preserves the public feed contract while giving every runtime one
  // unambiguous, bounded parser rather than a second YAML parser surface.
  return `${JSON.stringify(
    {
      schema_version: 1,
      version,
      channel,
      protocol_major: protocolMajor,
      generated_at: generatedAt,
      repository: repoUrl,
      artifacts: artifacts.map((artifact) => ({
        component: artifact.component,
        os: artifact.os,
        architecture: artifact.architecture,
        package: artifact.package,
        filename: artifact.filename,
        url: artifact.url,
        size: artifact.size,
        sha256: artifact.sha256,
        ...(artifact.releaseSignatureUrl
          ? { signature_url: artifact.releaseSignatureUrl }
          : {}),
      })),
    },
    null,
    2,
  )}
`;
}

function buildTauriManifest({
  artifacts,
  generatedAt,
  notes,
  requireSignatures,
  version,
}) {
  const platforms = {};
  const candidates = artifacts
    .filter(
      (artifact) =>
        artifact.component === "admin" &&
        (artifact.package === "appimage" || artifact.package === "nsis"),
    )
    .sort((left, right) => packagePriority(left) - packagePriority(right));
  for (const artifact of candidates) {
    const platform = `${artifact.os}-${artifact.architecture}`;
    if (platforms[platform]) continue;
    if (!artifact.tauriSignature) {
      if (requireSignatures) {
        throw new Error(`Missing Tauri signature for ${artifact.filename}`);
      }
      continue;
    }
    platforms[platform] = {
      signature: artifact.tauriSignature,
      url: artifact.url,
    };
  }
  if (requireSignatures) {
    for (const platform of [
      "linux-x86_64",
      "windows-x86_64",
      "windows-aarch64",
    ]) {
      if (!platforms[platform]) {
        throw new Error(`Missing signed Admin updater artifact for ${platform}`);
      }
    }
  }
  return {
    version,
    notes,
    pub_date: generatedAt,
    platforms,
  };
}

function validateReleaseSignatures(artifacts) {
  const missing = artifacts
    .filter((artifact) => !artifact.releaseSignatureUrl)
    .map((artifact) => artifact.filename);
  if (missing.length > 0) {
    throw new Error(
      `Missing Minisign release signatures for ${missing.join(", ")}`,
    );
  }
}

function packagePriority(artifact) {
  if (artifact.package === "nsis") return 0;
  if (artifact.package === "appimage") return 1;
  return 10;
}

function validateCompleteness(artifacts) {
  const actual = new Set(
    artifacts.map(
      (artifact) =>
        `${artifact.component}:${artifact.os}:${artifact.architecture}`,
    ),
  );
  const expected = [
    "server:linux:x86_64",
    "client:linux:x86_64",
    "client:windows:x86_64",
    "client:windows:aarch64",
    "admin:linux:x86_64",
    "admin:windows:x86_64",
    "admin:windows:aarch64",
  ];
  const missing = expected.filter((item) => !actual.has(item));
  if (missing.length > 0) {
    throw new Error(`Release is incomplete; missing ${missing.join(", ")}`);
  }
}

function writeAtomic(destination, contents) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, contents, { encoding: "utf8", mode: 0o644 });
  fs.renameSync(temporary, destination);
}
