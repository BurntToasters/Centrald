import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  compareSemver,
  parseSemver,
  releaseTimestamp,
} from "../lib/release-metadata.js";

test("release timestamps honor reproducible build inputs", () => {
  assert.equal(
    releaseTimestamp({
      CENTRALD_RELEASE_TIMESTAMP: "2026-08-08T01:02:03-07:00",
    }),
    "2026-08-08T08:02:03.000Z",
  );
  assert.equal(
    releaseTimestamp({ SOURCE_DATE_EPOCH: "0" }),
    "1970-01-01T00:00:00.000Z",
  );
  assert.throws(
    () => releaseTimestamp({ SOURCE_DATE_EPOCH: "1.5" }),
    /non-negative integer/u,
  );
});

test("semantic version comparison follows prerelease precedence", () => {
  const ordered = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
  ];
  for (let index = 1; index < ordered.length; index += 1) {
    assert.equal(compareSemver(ordered[index - 1], ordered[index]), -1);
    assert.equal(compareSemver(ordered[index], ordered[index - 1]), 1);
  }
  assert.equal(compareSemver("1.0.0+build.1", "1.0.0+build.2"), 0);
  assert.equal(compareSemver("1.0.0-alpha.10", "1.0.0-alpha.2"), 1);
});

test("semantic version parser rejects ambiguous numeric identifiers", () => {
  assert.throws(() => parseSemver("01.2.3"), /Invalid Semantic Versioning/u);
  assert.throws(() => parseSemver("1.2.3-alpha.01"), /leading zeroes/u);
  assert.throws(() => parseSemver("v1.2.3"), /Invalid Semantic Versioning/u);
});

test("manifest generation is reproducible for one release timestamp", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "centrald-manifest-test-"));
  try {
    await mkdir(path.join(root, "release", "artifacts"), { recursive: true });
    await mkdir(path.join(root, "crates", "centrald-protocol", "src"), {
      recursive: true,
    });
    await writeFile(
      path.join(root, "centrald.config"),
      "REPO_URL=https://github.com/BurntToasters/centrald\nRELEASE_CHANNEL=beta\n",
    );
    await writeFile(
      path.join(root, "package.json"),
      '{"version":"1.2.3","type":"module"}\n',
    );
    await writeFile(
      path.join(root, "crates", "centrald-protocol", "src", "lib.rs"),
      "pub const PROTOCOL_MAJOR: u32 = 1;\n",
    );
    await writeFile(
      path.join(
        root,
        "release",
        "artifacts",
        "centrald-client_1.2.3_linux_x86_64.zip",
      ),
      "fixture",
    );
    const generator = fileURLToPath(
      new URL("../generate-manifests.js", import.meta.url),
    );
    const environment = {
      ...process.env,
      CENTRALD_RELEASE_TIMESTAMP: "2026-08-08T08:00:00Z",
    };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const result = spawnSync(
        process.execPath,
        [
          generator,
          "--artifacts-dir",
          "release/artifacts",
          "--output-dir",
          "release",
        ],
        { cwd: root, env: environment, encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      const shared = await readFile(
        path.join(root, "release", "centrald-release.yml"),
      );
      const updater = await readFile(
        path.join(root, "release", "centrald-admin-updater.json"),
      );
      if (attempt === 0) {
        environment.EXPECTED_SHARED = shared.toString("base64");
        environment.EXPECTED_UPDATER = updater.toString("base64");
      } else {
        assert.equal(shared.toString("base64"), environment.EXPECTED_SHARED);
        assert.equal(updater.toString("base64"), environment.EXPECTED_UPDATER);
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("version bump updates package.json, Cargo.toml, and tauri.conf.json in lockstep", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "centrald-bump-test-"));
  try {
    await writeFile(
      path.join(root, "package.json"),
      '{"version":"0.1.0-alpha.1","type":"module"}\n',
    );
    await writeFile(
      path.join(root, "Cargo.toml"),
      '[workspace.package]\nversion = "0.1.0-alpha.1"\n',
    );
    await mkdir(path.join(root, "apps", "admin", "src-tauri"), {
      recursive: true,
    });
    await writeFile(
      path.join(root, "apps", "admin", "src-tauri", "tauri.conf.json"),
      '{"version":"0.1.0-alpha.1"}\n',
    );
    const bumper = fileURLToPath(
      new URL("../bump-version.js", import.meta.url),
    );
    const result = spawnSync(process.execPath, [bumper, "0.1.0-alpha.2"], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(
      JSON.parse(await readFile(path.join(root, "package.json"), "utf8"))
        .version,
      "0.1.0-alpha.2",
    );
    const cargo = await readFile(path.join(root, "Cargo.toml"), "utf8");
    assert.match(cargo, /version = "0\.1\.0-alpha\.2"/);
    assert.doesNotMatch(cargo, /0\.1\.0-alpha\.1/);
    assert.equal(
      JSON.parse(
        await readFile(
          path.join(root, "apps", "admin", "src-tauri", "tauri.conf.json"),
          "utf8",
        ),
      ).version,
      "0.1.0-alpha.2",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("version bump rejects invalid versions and unknown current versions", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "centrald-bump-reject-"));
  try {
    await writeFile(
      path.join(root, "package.json"),
      '{"version":"0.1.0-alpha.1","type":"module"}\n',
    );
    await writeFile(
      path.join(root, "Cargo.toml"),
      '[workspace.package]\nversion = "0.1.0-alpha.1"\n',
    );
    await mkdir(path.join(root, "apps", "admin", "src-tauri"), {
      recursive: true,
    });
    await writeFile(
      path.join(root, "apps", "admin", "src-tauri", "tauri.conf.json"),
      '{"version":"0.1.0-alpha.1"}\n',
    );
    const bumper = fileURLToPath(
      new URL("../bump-version.js", import.meta.url),
    );
    const invalid = spawnSync(process.execPath, [bumper, "not-a-version"], {
      cwd: root,
      encoding: "utf8",
    });
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /not valid strict SemVer/);
    const same = spawnSync(process.execPath, [bumper, "0.1.0-alpha.1"], {
      cwd: root,
      encoding: "utf8",
    });
    assert.notEqual(same.status, 0);
    assert.match(same.stderr, /nothing to bump/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
