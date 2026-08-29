import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { commandExists, run } from "./command.js";
import { loadBuildConfig } from "./lib/build-config.js";
import { assertManifestChannel } from "./lib/channel-manifest.js";

// Uploads the signed channel manifests to the S3-compatible CDN bucket
// (DigitalOcean Spaces or any S3 endpoint) so binaries that bake
// <CDN_BASE_URL>/<channel> resolve their update pointers.
//
// The GitHub centrald-channels branch remains the source of truth; this is a
// mirror of the same bytes, run automatically as the last publish step.
//
// Requires the aws CLI on PATH and the S3 credentials in the environment:
//   CENTRALD_S3_ENDPOINT   e.g. https://nyc3.digitaloceanspaces.com
//   CENTRALD_S3_BUCKET     e.g. updated-centrald
//   CENTRALD_S3_REGION     optional; defaults to us-east-1 (Spaces convention)
//   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (read by the aws CLI)

const root = process.cwd();
const options = parseArguments(process.argv.slice(2));
const channel = options.channel;
const config = loadBuildConfig(root, { releaseChannel: channel });
const releaseChannel = channel || config.releaseChannel;
if (!releaseChannel) {
  throw new Error(
    "No release channel determined. Pass --channel <stable|alpha|beta> or configure RELEASE_CHANNEL in centrald.config.",
  );
}

if (!config.cdnBaseUrl) {
  throw new Error(
    "CDN_BASE_URL is not configured in centrald.config; nothing to sync.",
  );
}

const endpoint = process.env.CENTRALD_S3_ENDPOINT?.trim();
const bucket = process.env.CENTRALD_S3_BUCKET?.trim();
const region = process.env.CENTRALD_S3_REGION?.trim() || "us-east-1";
if (!endpoint) {
  throw new Error(
    "CENTRALD_S3_ENDPOINT is missing. Set it in .env (e.g. https://nyc3.digitaloceanspaces.com).",
  );
}
if (!bucket) {
  throw new Error(
    "CENTRALD_S3_BUCKET is missing. Set it in .env to the target bucket name.",
  );
}
if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
  throw new Error(
    "S3 credentials are missing. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env.",
  );
}
if (!commandExists("aws", ["--version"])) {
  throw new Error(
    "The aws CLI is required for CDN sync. Install it with: winget install Amazon.AWSCli",
  );
}
if (!config.minisignPublicKey) {
  throw new Error(
    "centrald.config must contain MINISIGN_PUBLIC_KEY before CDN sync.",
  );
}
if (!commandExists("minisign", ["-v"])) {
  throw new Error(
    "minisign is required to verify channel manifests before CDN sync.",
  );
}

const sourceDirectory = options.fromDir
  ? path.resolve(root, options.fromDir)
  : path.join(root, "release");
const files = [
  config.releaseManifest,
  `${config.releaseManifest}.minisig`,
  config.tauriUpdateManifest,
  `${config.tauriUpdateManifest}.minisig`,
].map((name) => path.join(sourceDirectory, name));
for (const file of files) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`Missing release manifest file ${file}`);
  }
  if (fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(`Refusing symbolic-link release manifest ${file}`);
  }
}

verifyManifestSignatures(files);
assertManifestChannel(
  fs.readFileSync(path.join(sourceDirectory, config.releaseManifest), "utf8"),
  releaseChannel,
);

console.log(
  `Syncing ${releaseChannel} channel manifests to s3://${bucket}/${releaseChannel}/...`,
);
for (const file of files) {
  const destination = `s3://${bucket}/${releaseChannel}/${path.basename(file)}`;
  run("aws", [
    "s3",
    "cp",
    file,
    destination,
    "--endpoint-url",
    endpoint,
    "--region",
    region,
    "--no-progress",
  ]);
}
console.log(
  `Synced ${files.length} ${releaseChannel} channel manifests to ${config.cdnBaseUrl}/${releaseChannel}/`,
);

function parseArguments(args) {
  const result = { channel: "", fromDir: "" };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--channel") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error("--channel requires a value");
      }
      if (result.channel)
        throw new Error("--channel may be provided only once");
      result.channel = value;
    } else if (argument === "--from-dir") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error("--from-dir requires a value");
      }
      if (result.fromDir)
        throw new Error("--from-dir may be provided only once");
      result.fromDir = value;
    } else {
      throw new Error(`Unknown argument ${argument}`);
    }
  }
  return result;
}

function verifyManifestSignatures(allFiles) {
  for (const file of allFiles) {
    if (file.endsWith(".minisig")) continue;
    const signature = `${file}.minisig`;
    execFileSync(
      "minisign",
      ["-V", "-P", config.minisignPublicKey, "-m", file, "-x", signature],
      { stdio: "inherit" },
    );
  }
}
