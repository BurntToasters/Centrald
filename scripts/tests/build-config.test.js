import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  artifactBaseUrl,
  loadBuildConfig,
  releaseManifestUrl,
} from "../lib/build-config.js";

function temporaryConfig(contents) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "centrald-config-"));
  fs.writeFileSync(path.join(root, "centrald.config"), contents);
  return root;
}

test("derives GitHub latest and immutable release URLs", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=stable\n",
  );
  const config = loadBuildConfig(root);
  assert.equal(
    releaseManifestUrl(config),
    "https://github.com/example/centrald/releases/latest/download/centrald-release.yml",
  );
  assert.equal(
    artifactBaseUrl(config, "1.2.3"),
    "https://github.com/example/centrald/releases/download/v1.2.3",
  );
  fs.rmSync(root, { recursive: true });
});

test("derives mutable GitHub prerelease channel URLs from the channel branch", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=prerelease\n",
  );
  const config = loadBuildConfig(root);
  assert.equal(
    releaseManifestUrl(config),
    "https://raw.githubusercontent.com/example/centrald/centrald-channels/channels/prerelease/latest/centrald-release.yml",
  );
  fs.rmSync(root, { recursive: true });
});

test("derives per-channel CDN URLs for every channel when CDN_BASE_URL is set", () => {
  const root = temporaryConfig(
    [
      "REPO_URL=https://github.com/example/centrald",
      "RELEASE_CHANNEL=stable",
      "CDN_BASE_URL=https://updated.example.test",
    ].join("\n"),
  );
  const stable = loadBuildConfig(root);
  assert.equal(
    releaseManifestUrl(stable),
    "https://updated.example.test/stable/centrald-release.yml",
  );
  assert.equal(stable.cdnBaseUrl, "https://updated.example.test");

  const beta = loadBuildConfig(root, { releaseChannel: "beta" });
  assert.equal(
    releaseManifestUrl(beta),
    "https://updated.example.test/beta/centrald-release.yml",
  );
  assert.equal(beta.releaseChannel, "beta");
  fs.rmSync(root, { recursive: true });
});

test("release channel override beats the tracked configuration", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=stable\n",
  );
  const config = loadBuildConfig(root, { releaseChannel: "alpha" });
  assert.equal(config.releaseChannel, "alpha");
  assert.match(
    releaseManifestUrl(config),
    /channels\/alpha\/latest\/centrald-release\.yml$/u,
  );
  fs.rmSync(root, { recursive: true });
});

test("without CDN, stable stays on the GitHub latest pointer", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=stable\n",
  );
  const config = loadBuildConfig(root);
  assert.equal(config.cdnBaseUrl, "");
  assert.equal(
    releaseManifestUrl(config),
    "https://github.com/example/centrald/releases/latest/download/centrald-release.yml",
  );
  fs.rmSync(root, { recursive: true });
});

test("supports static object storage layouts", () => {
  const root = temporaryConfig(
    [
      "REPO_URL=https://downloads.example.test/centrald",
      "UPDATE_BASE_URL=https://cdn.example.test/centrald/latest",
      "ARTIFACT_BASE_URL_TEMPLATE=https://cdn.example.test/centrald/{version}",
      "RELEASE_CHANNEL=prerelease",
    ].join("\n"),
  );
  const config = loadBuildConfig(root);
  assert.equal(
    artifactBaseUrl(config, "0.2.0-alpha.1"),
    "https://cdn.example.test/centrald/0.2.0-alpha.1",
  );
  fs.rmSync(root, { recursive: true });
});

test("rejects unknown keys and insecure URLs", () => {
  const unknown = temporaryConfig(
    "REPO_URL=https://example.test/centrald\nDATABASE_PASSWORD=nope\n",
  );
  assert.throws(() => loadBuildConfig(unknown), /unknown key/u);
  fs.rmSync(unknown, { recursive: true });

  const insecure = temporaryConfig("REPO_URL=http://example.test/centrald\n");
  assert.throws(() => loadBuildConfig(insecure), /HTTPS/u);
  fs.rmSync(insecure, { recursive: true });
});
