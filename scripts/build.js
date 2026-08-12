import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { run } from "./command.js";
import { loadBuildConfig, tauriManifestUrl } from "./lib/build-config.js";
import {
  cleanGeneratedDirectory,
  ensureGeneratedDirectory,
} from "./lib/safe-path.js";

const root = process.cwd();
const options = parseArguments(process.argv.slice(2));
const supported = new Set(["windows-x64", "windows-arm64", "linux-x64", "all"]);
if (!supported.has(options.target)) {
  throw new Error(`Unsupported --target ${JSON.stringify(options.target)}`);
}
if (options.native && options.target !== "linux-x64") {
  throw new Error("--native is supported only with --target linux-x64");
}
if (options.signed && options.target === "all") {
  throw new Error(
    "Signed all-platform releases must run as separate native platform jobs.",
  );
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const version = packageJson.version;
const buildConfig = loadBuildConfig(root);
ensureGeneratedDirectory(root, "dist");

if (options.signed) validateSigningEnvironment(buildConfig);

if (options.target === "all") {
  requirePlatform("win32", "--target all");
  buildWindows("x64");
  buildWindows("arm64");
  buildLinuxDocker();
} else if (options.target === "windows-x64") {
  requirePlatform("win32", options.target);
  buildWindows("x64");
} else if (options.target === "windows-arm64") {
  requirePlatform("win32", options.target);
  buildWindows("arm64");
} else if (options.native) {
  requirePlatform("linux", "--native Linux build");
  buildLinuxNative();
} else {
  buildLinuxDocker();
}

function parseArguments(args) {
  const result = { target: "", signed: false, native: false };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--target") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error("--target requires a value");
      }
      result.target = value;
    } else if (argument === "--signed") {
      result.signed = true;
    } else if (argument === "--native") {
      result.native = true;
    } else {
      throw new Error(`Unknown argument ${argument}`);
    }
  }
  return result;
}

function validateSigningEnvironment(config) {
  if (!process.env.TAURI_SIGNING_PRIVATE_KEY) {
    throw new Error(
      "--signed requires TAURI_SIGNING_PRIVATE_KEY in the process environment.",
    );
  }
  if (!config.tauriUpdaterPubkey.trim()) {
    throw new Error(
      "--signed requires the public Tauri key in centrald.config as TAURI_UPDATER_PUBKEY.",
    );
  }
}

function buildWindows(architecture) {
  const target = architecture === "x64" ? "windows-x64" : "windows-arm64";
  const rustTarget =
    architecture === "x64"
      ? "x86_64-pc-windows-msvc"
      : "aarch64-pc-windows-msvc";
  const manifestArchitecture = architecture === "x64" ? "x86_64" : "aarch64";
  const outputRelative = `dist/${target}`;
  cleanGeneratedDirectory(root, outputRelative);
  const output = ensureGeneratedDirectory(root, outputRelative);

  run("rustup", ["target", "add", rustTarget]);
  run("cargo", [
    "build",
    "--locked",
    "--release",
    "--target",
    rustTarget,
    "-p",
    "centrald-client",
  ]);

  const releaseConfig = createTauriReleaseConfig();
  try {
    const tauriArgs = [
      "tauri",
      "build",
      "--target",
      rustTarget,
      "--bundles",
      "nsis",
    ];
    if (releaseConfig) tauriArgs.push("--config", releaseConfig);
    run("npx", tauriArgs, { cwd: path.join(root, "apps/admin") });
  } finally {
    removeTemporaryConfig(releaseConfig);
  }

  const clientBinary = requireRegularFile(
    path.join(root, "target", rustTarget, "release", "centrald-client.exe"),
    "Windows client binary",
  );
  const clientZip = path.join(
    output,
    `centrald-client_${version}_windows_${manifestArchitecture}.zip`,
  );
  buildWindowsClientZip(clientBinary, clientZip, output);

  const nsisDirectory = path.join(
    root,
    "target",
    rustTarget,
    "release",
    "bundle",
    "nsis",
  );
  const installer = findSingleArtifact(
    nsisDirectory,
    (file) => file.toLowerCase().endsWith(".exe"),
    "CentralD Admin NSIS installer",
  );
  const adminArtifact = path.join(
    output,
    `centrald-admin_${version}_windows_${manifestArchitecture}.exe`,
  );
  copyArtifact(installer, adminArtifact, 0o755);
  copySignatureIfPresent(installer, adminArtifact);

  console.log(`Created ${clientZip}`);
  console.log(`Created ${adminArtifact}`);
}

function buildWindowsClientZip(clientBinary, destination, output) {
  const staging = path.join(output, `.client-staging-${process.pid}`);
  if (fs.existsSync(staging)) {
    throw new Error(`Refusing existing client staging directory: ${staging}`);
  }
  try {
    fs.mkdirSync(staging, { recursive: false, mode: 0o700 });
    copyArtifact(
      clientBinary,
      path.join(staging, "centrald-client.exe"),
      0o755,
    );
    copyArtifact(
      requireRegularFile(
        path.join(root, "deploy/windows/install-client.ps1"),
        "Windows install script",
      ),
      path.join(staging, "install-client.ps1"),
      0o644,
    );
    copyArtifact(
      requireRegularFile(
        path.join(root, "deploy/windows/README.txt"),
        "Windows client README",
      ),
      path.join(staging, "README.txt"),
      0o644,
    );
    run("tar.exe", ["-a", "-c", "-f", destination, "-C", staging, "."]);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function buildLinuxDocker() {
  if (options.signed) {
    throw new Error(
      "Signed Linux artifacts must use --target linux-x64 --native so the Tauri signing key is not passed as a Docker build argument.",
    );
  }
  cleanGeneratedDirectory(root, "dist/linux-x64");
  run("docker", [
    "build",
    "--file",
    "docker/linux-builder.Dockerfile",
    "--output",
    "type=local,dest=dist/linux-x64",
    ".",
  ]);
}

function buildLinuxNative() {
  const rustTarget = "x86_64-unknown-linux-gnu";
  run("rustup", ["target", "add", rustTarget]);
  run("cargo", [
    "build",
    "--locked",
    "--release",
    "--target",
    rustTarget,
    "-p",
    "centrald-server",
    "-p",
    "centrald-client",
  ]);
  const releaseConfig = createTauriReleaseConfig();
  try {
    const tauriArgs = [
      "tauri",
      "build",
      "--target",
      rustTarget,
      "--bundles",
      "appimage",
    ];
    if (releaseConfig) tauriArgs.push("--config", releaseConfig);
    run("npx", tauriArgs, { cwd: path.join(root, "apps/admin") });
  } finally {
    removeTemporaryConfig(releaseConfig);
  }
  run("node", [
    "scripts/package-linux.js",
    "--target-dir",
    `target/${rustTarget}/release`,
    "--output",
    "dist/linux-x64",
  ]);
}

function createTauriReleaseConfig() {
  if (!options.signed) return "";
  const destination = path.join(
    root,
    "dist",
    `.tauri-release-config-${process.pid}.json`,
  );
  const value = {
    bundle: { createUpdaterArtifacts: true },
    plugins: {
      updater: {
        pubkey: buildConfig.tauriUpdaterPubkey,
        endpoints: [tauriManifestUrl(buildConfig)],
      },
    },
  };
  fs.writeFileSync(destination, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  return destination;
}

function removeTemporaryConfig(file) {
  if (!file) return;
  fs.rmSync(file, { force: false });
}

function requirePlatform(expected, operation) {
  if (process.platform !== expected) {
    throw new Error(
      `${operation} requires ${expected}; current platform is ${process.platform}.`,
    );
  }
}

function requireRegularFile(file, label) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    throw new Error(`Missing ${label}: ${file}`);
  }
  if (fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(`Refusing symbolic-link ${label}: ${file}`);
  }
  return file;
}

function findSingleArtifact(directory, predicate, label) {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) {
    throw new Error(`Missing ${label} directory: ${directory}`);
  }
  const matches = fs
    .readdirSync(directory, { withFileTypes: true })
    .filter(
      (entry) => entry.isFile() && predicate(path.join(directory, entry.name)),
    )
    .map((entry) => path.join(directory, entry.name));
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one ${label} in ${directory}; found ${matches.length}`,
    );
  }
  return requireRegularFile(matches[0], label);
}

function copyArtifact(source, destination, mode) {
  fs.copyFileSync(source, destination);
  fs.chmodSync(destination, mode);
}

function copySignatureIfPresent(source, destination) {
  const signature = `${source}.sig`;
  if (!fs.existsSync(signature)) {
    if (options.signed) {
      throw new Error(
        `Tauri did not generate the required signature: ${signature}`,
      );
    }
    return;
  }
  copyArtifact(
    requireRegularFile(signature, "Tauri updater signature"),
    `${destination}.sig`,
    0o644,
  );
}
