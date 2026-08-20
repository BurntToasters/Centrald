import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  artifactBaseUrl,
  detectChannelFromVersion,
  loadBuildConfig,
  releaseManifestUrl,
} from "../lib/build-config.js";

function temporaryConfig(contents, version = "1.2.3") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "centrald-config-"));
  fs.writeFileSync(path.join(root, "centrald.config"), contents);
  fs.writeFileSync(
    path.join(root, "package.json"),
    `${JSON.stringify({ version, name: "fixture" })}\n`,
  );
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

test("derives mutable GitHub beta channel URLs from the channel branch", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=beta\n",
  );
  const config = loadBuildConfig(root);
  assert.equal(
    releaseManifestUrl(config),
    "https://raw.githubusercontent.com/example/centrald/centrald-channels/channels/beta/latest/centrald-release.yml",
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

test("empty releaseChannel override does not mask CENTRALD_RELEASE_CHANNEL", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=stable\n",
  );
  const previous = process.env.CENTRALD_RELEASE_CHANNEL;
  process.env.CENTRALD_RELEASE_CHANNEL = "beta";
  try {
    const config = loadBuildConfig(root, { releaseChannel: "" });
    assert.equal(config.releaseChannel, "beta");
    assert.equal(config.channelSource, "override");
  } finally {
    if (previous === undefined) delete process.env.CENTRALD_RELEASE_CHANNEL;
    else process.env.CENTRALD_RELEASE_CHANNEL = previous;
    fs.rmSync(root, { recursive: true });
  }
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
      "RELEASE_CHANNEL=beta",
    ].join("\n"),
  );
  const config = loadBuildConfig(root);
  assert.equal(
    artifactBaseUrl(config, "0.2.0-alpha.1"),
    "https://cdn.example.test/centrald/0.2.0-alpha.1",
  );
  fs.rmSync(root, { recursive: true });
});

test("auto-detects the channel from the package version when unset", () => {
  const stable = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\n",
    "1.2.3",
  );
  assert.equal(loadBuildConfig(stable).releaseChannel, "stable");
  assert.equal(loadBuildConfig(stable).channelSource, "detected");
  fs.rmSync(stable, { recursive: true });

  const alpha = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nCDN_BASE_URL=https://updated.example.test\n",
    "0.2.0-alpha.1",
  );
  const alphaConfig = loadBuildConfig(alpha);
  assert.equal(alphaConfig.releaseChannel, "alpha");
  assert.equal(alphaConfig.channelSource, "detected");
  assert.equal(
    releaseManifestUrl(alphaConfig),
    "https://updated.example.test/alpha/centrald-release.yml",
  );
  fs.rmSync(alpha, { recursive: true });

  const beta = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\n",
    "0.2.0-beta.2",
  );
  assert.equal(loadBuildConfig(beta).releaseChannel, "beta");
  fs.rmSync(beta, { recursive: true });
});

test("detectChannelFromVersion maps prerelease identifiers to channels", () => {
  assert.equal(detectChannelFromVersion("1.2.3"), "stable");
  assert.equal(detectChannelFromVersion("1.2.3-alpha.1"), "alpha");
  assert.equal(detectChannelFromVersion("1.2.3-beta.2"), "beta");
  assert.equal(detectChannelFromVersion("1.2.3-Alpha.1"), "alpha");
  assert.equal(detectChannelFromVersion("1.2.3-"), "stable");
});

test("detectChannelFromVersion rejects channels outside stable/alpha/beta", () => {
  assert.throws(
    () => detectChannelFromVersion("1.2.3-rc.1"),
    /unsupported channel rc/,
  );
  assert.throws(
    () => detectChannelFromVersion("1.2.3-canary.1"),
    /unsupported channel canary/,
  );
});

test("loadBuildConfig rejects non-central channels from any source", () => {
  const root = temporaryConfig(
    "REPO_URL=https://github.com/example/centrald\nRELEASE_CHANNEL=canary\n",
  );
  assert.throws(
    () => loadBuildConfig(root),
    /must be one of stable, alpha, beta/,
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

test("CDN_BASE_URL wins over UPDATE_BASE_URL for feed derivation", () => {
  const root = temporaryConfig(
    [
      "REPO_URL=https://github.com/example/centrald",
      "UPDATE_BASE_URL=https://cdn.example.test/centrald/latest",
      "CDN_BASE_URL=https://updated.example.test",
      "RELEASE_CHANNEL=beta",
    ].join("\n"),
  );
  const config = loadBuildConfig(root);
  assert.equal(
    releaseManifestUrl(config),
    "https://updated.example.test/beta/centrald-release.yml",
  );
  fs.rmSync(root, { recursive: true });
});
