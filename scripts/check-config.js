import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  artifactBaseUrl,
  loadBuildConfig,
  releaseManifestUrl,
  tauriManifestUrl,
} from "./lib/build-config.js";

const root = process.cwd();
const config = loadBuildConfig(root);
const version = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
).version;

console.log(`Repository: ${config.repoUrl}`);
console.log(
  `Channel: ${config.releaseChannel}${config.channelSource === "detected" ? " (auto-detected from version)" : ""}`,
);
console.log(`Release manifest: ${releaseManifestUrl(config)}`);
console.log(`Admin updater manifest: ${tauriManifestUrl(config)}`);
console.log(`Immutable artifacts: ${artifactBaseUrl(config, version)}`);
console.log(
  `CDN: ${config.cdnBaseUrl ? `${config.cdnBaseUrl}/${config.releaseChannel} (channel manifests mirrored to S3)` : "not configured (channel manifests served from GitHub)"}`,
);
console.log(
  `Tauri updater key: ${config.tauriUpdaterPubkey ? "configured" : "not configured (signed release builds disabled)"}`,
);
console.log(
  `Minisign key: ${config.minisignPublicKey ? "configured" : "not configured (release artifact signing disabled)"}`,
);
