import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { commandExists } from "./command.js";
import { loadBuildConfig } from "./lib/build-config.js";
import { resolveGeneratedTarget } from "./lib/safe-path.js";

const root = process.cwd();
const options = parseArguments(process.argv.slice(2));
const config = loadBuildConfig(root);
const artifactsDir = resolveGeneratedTarget(root, options.artifactsDir);
const secretKey = path.resolve(
  root,
  options.secretKey ?? process.env.MINISIGN_SECRET_KEY_FILE ?? "",
);

if (!config.minisignPublicKey) {
  throw new Error(
    "centrald.config must contain MINISIGN_PUBLIC_KEY before release signing.",
  );
}
if (!commandExists("minisign", ["-v"])) {
  throw new Error("minisign is required to sign release artifacts.");
}
if (!options.secretKey && !process.env.MINISIGN_SECRET_KEY_FILE) {
  throw new Error(
    "Provide --secret-key or MINISIGN_SECRET_KEY_FILE. Never put the private key in centrald.config.",
  );
}
requireRegularFile(secretKey, "Minisign secret key");
if (!fs.existsSync(artifactsDir) || !fs.statSync(artifactsDir).isDirectory()) {
  throw new Error(`Artifact directory does not exist: ${artifactsDir}`);
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const artifacts = fs
  .readdirSync(artifactsDir, { withFileTypes: true })
  .filter((entry) => entry.isFile() && isCanonicalArtifact(entry.name))
  .map((entry) => path.join(artifactsDir, entry.name))
  .sort();
if (artifacts.length === 0) {
  throw new Error(`No canonical CentralD artifacts found in ${artifactsDir}`);
}

for (const artifact of artifacts) {
  signFile(
    artifact,
    `centrald ${packageJson.version} ${path.basename(artifact)}`,
  );
}

// Sign the mutable channel manifests as well, so clients and servers can
// verify the manifest itself before trusting its channel/version fields.
const releaseDirectory = path.resolve(root, options.outputDir);
let signedManifestCount = 0;
for (const manifestName of [
  config.releaseManifest,
  config.tauriUpdateManifest,
]) {
  const manifest = path.join(releaseDirectory, manifestName);
  if (!fs.existsSync(manifest)) {
    continue;
  }
  requireRegularFile(manifest, "Release manifest");
  signFile(manifest, `centrald ${packageJson.version} ${manifestName}`);
  signedManifestCount += 1;
}

console.log(
  `Signed and verified ${artifacts.length} release artifacts and ${signedManifestCount} manifests.`,
);

function signFile(file, trustedComment) {
  requireRegularFile(file, "Release file");
  const signature = `${file}.minisig`;
  fs.rmSync(signature, { force: true });
  const signingArguments = [
    "-S",
    "-s",
    secretKey,
    "-m",
    file,
    "-x",
    signature,
    "-t",
    trustedComment,
  ];
  if (options.unprotectedKey) signingArguments.splice(1, 0, "-W");
  execFileSync("minisign", signingArguments, { stdio: "inherit" });
  fs.chmodSync(signature, 0o644);
  execFileSync(
    "minisign",
    ["-V", "-P", config.minisignPublicKey, "-m", file, "-x", signature],
    { stdio: "inherit" },
  );
}

function parseArguments(args) {
  const result = {
    artifactsDir: "release/artifacts",
    outputDir: "release",
    secretKey: null,
    unprotectedKey: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--artifacts-dir") {
      result.artifactsDir = requiredValue(args, ++index, argument);
    } else if (argument === "--output-dir") {
      result.outputDir = requiredValue(args, ++index, argument);
    } else if (argument === "--secret-key") {
      result.secretKey = requiredValue(args, ++index, argument);
    } else if (argument === "--unprotected-key") {
      result.unprotectedKey = true;
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

function isCanonicalArtifact(filename) {
  return /^centrald-(server|client|admin)_.+_(linux|windows)_(x86_64|aarch64)\.(deb|msi|exe|AppImage|zip|tar\.gz)$/u.test(
    filename,
  );
}

function requireRegularFile(file, description) {
  if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`${description} is missing or not a regular file: ${file}`);
  }
  if (fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(
      `Refusing symbolic-link ${description.toLowerCase()}: ${file}`,
    );
  }
}
