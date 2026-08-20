import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { run } from "./command.js";
import { loadBuildConfig, tauriManifestUrl } from "./lib/build-config.js";
import { ensureDockerEngine, dockerExecutable } from "./lib/docker-engine.js";
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
if (options.container && options.native) {
  throw new Error("--container and --native are mutually exclusive");
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const version = packageJson.version;
const buildConfig = loadBuildConfig(root, {
  releaseChannel: options.channel,
});
if (options.channel) {
  // build.rs bakes CENTRALD_RELEASE_CHANNEL; native cargo children inherit it
  // from the process environment. Container builds receive it as a build arg
  // (public value, not a secret).
  process.env.CENTRALD_RELEASE_CHANNEL = options.channel;
}
ensureGeneratedDirectory(root, "dist");

if (options.signed) validateSigningEnvironment(buildConfig);

if (options.target === "all") {
  if (options.container) {
    buildAllContainerized();
  } else {
    requirePlatform("win32", "--target all");
    buildWindows("x64");
    buildWindows("arm64");
    buildLinuxDocker();
  }
} else if (options.target === "windows-x64") {
  if (options.container) {
    buildWindowsContainer(["windows-x64"]);
  } else {
    requirePlatform("win32", options.target);
    buildWindows("x64");
  }
} else if (options.target === "windows-arm64") {
  if (options.container) {
    buildWindowsContainer(["windows-arm64"]);
  } else {
    requirePlatform("win32", options.target);
    buildWindows("arm64");
  }
} else if (options.native) {
  requirePlatform("linux", "--native Linux build");
  buildLinuxNative();
} else {
  buildLinuxDocker();
}

function parseArguments(args) {
  const result = {
    target: "",
    signed: false,
    native: false,
    container: false,
    channel: "",
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--target") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error("--target requires a value");
      }
      result.target = value;
    } else if (argument === "--channel") {
      const value = args[++index];
      if (!value || value.startsWith("--")) {
        throw new Error("--channel requires a value");
      }
      result.channel = value;
    } else if (argument === "--signed") {
      result.signed = true;
    } else if (argument === "--native") {
      result.native = true;
    } else if (argument === "--container") {
      result.container = true;
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
  const stagingDirectory = path.join(output, `.client-staging-${process.pid}`);
  if (fs.existsSync(stagingDirectory)) {
    throw new Error(
      `Refusing existing client staging directory: ${stagingDirectory}`,
    );
  }
  const stagingRelative = path
    .relative(root, stagingDirectory)
    .replaceAll("\\", "/");
  ensureGeneratedDirectory(root, stagingRelative);
  const staging = path.join(stagingDirectory, "root");
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
    cleanGeneratedDirectory(root, stagingRelative);
  }
}

function buildLinuxDocker() {
  ensureDockerEngine("linux", "Linux builder");
  cleanGeneratedDirectory(root, "dist/linux-x64");
  run(dockerExecutable(), [
    "build",
    "--pull",
    ...dockerChannelArguments(),
    "--file",
    "docker/linux-builder.Dockerfile",
    "--output",
    "type=local,dest=dist/linux-x64",
    ".",
  ]);
  // The updater signing key must never enter a Docker build argument. The
  // Docker-built Linux AppImage is therefore signed on the host afterwards;
  // `tauri signer sign` reads TAURI_SIGNING_PRIVATE_KEY and the optional
  // TAURI_SIGNING_PRIVATE_KEY_PASSWORD from the process environment.
  if (options.signed) signHostUpdaterArtifact(findLinuxAppImage());
}

/// The channel is public build metadata; it is passed to container builds as
/// a build argument so the builder's build.rs bakes the overridden channel.
function dockerChannelArguments() {
  const channel = options.channel || process.env.CENTRALD_RELEASE_CHANNEL || "";
  return channel ? ["--build-arg", `CENTRALD_RELEASE_CHANNEL=${channel}`] : [];
}

/// Builds the Windows targets inside a Windows-container image and extracts the
/// artifacts with `docker create` + `docker cp`, so the host machine only ever
/// runs Docker and never the native MSVC/Rust toolchain. The image builds both
/// targets; only the requested architectures are extracted.
function buildWindowsContainer(architectures) {
  ensureDockerEngine("windows", "Windows container builder");
  run(dockerExecutable(), [
    "build",
    "--pull",
    ...dockerChannelArguments(),
    "--file",
    "docker/windows-builder.Dockerfile",
    "--tag",
    "centrald-windows-builder:latest",
    ".",
  ]);
  const containerName = `centrald-windows-extract-${process.pid}`;
  const stagingRelative = `dist/.windows-container-${process.pid}`;
  cleanGeneratedDirectory(root, stagingRelative);
  const staging = ensureGeneratedDirectory(root, stagingRelative);
  let containerCreated = false;
  try {
    run(dockerExecutable(), [
      "create",
      "--name",
      containerName,
      "centrald-windows-builder:latest",
    ]);
    containerCreated = true;
    for (const architecture of architectures) {
      const destination = `dist/${architecture}`;
      cleanGeneratedDirectory(root, destination);
      ensureGeneratedDirectory(root, destination);
      // Windows-container paths use drive letters and backslashes; docker cp
      // from a created (not started) container reads the image's filesystem.
      // The directory is copied whole into staging, then its contents are
      // moved, so the copy semantics do not depend on trailing separators.
      run(dockerExecutable(), [
        "cp",
        `${containerName}:C:\\src\\dist\\${architecture}`,
        staging,
      ]);
      const extracted = path.join(staging, architecture);
      if (!fs.existsSync(extracted) || !fs.statSync(extracted).isDirectory()) {
        throw new Error(
          `Windows container produced no ${architecture} artifact directory.`,
        );
      }
      for (const entry of fs.readdirSync(extracted, { withFileTypes: true })) {
        if (!entry.isFile()) continue;
        fs.copyFileSync(
          path.join(extracted, entry.name),
          path.join(root, destination, entry.name),
        );
      }
      console.log(
        `Extracted ${architecture} artifacts from the Windows container.`,
      );
    }
  } finally {
    try {
      if (containerCreated) {
        run(dockerExecutable(), ["rm", "-f", containerName]);
      }
    } finally {
      cleanGeneratedDirectory(root, stagingRelative);
    }
  }
  if (options.signed) {
    for (const architecture of architectures) {
      signHostUpdaterArtifact(
        findSingleArtifact(
          path.join(root, "dist", architecture),
          (file) => file.endsWith(".exe"),
          `CentralD Admin NSIS installer (${architecture})`,
        ),
      );
    }
  }
}

/// Builds every platform inside Docker containers: the Linux engine produces
/// the Linux artifacts, then the Windows engine produces both Windows targets.
/// Docker Desktop supports only one engine mode at a time, so the engine is
/// switched between the two container images.
function buildAllContainerized() {
  buildLinuxDocker();
  buildWindowsContainer(["windows-x64", "windows-arm64"]);
}

/// Signs a single updater artifact on the host with `tauri signer sign`. The
/// command reads TAURI_SIGNING_PRIVATE_KEY and the optional
/// TAURI_SIGNING_PRIVATE_KEY_PASSWORD from the process environment; a key held
/// as a file path is passed with -f and the env-var value cleared to avoid
/// clap's conflicts_with between -k and -f.
function signHostUpdaterArtifact(artifact) {
  const key = process.env.TAURI_SIGNING_PRIVATE_KEY ?? "";
  const args = ["tauri", "signer", "sign"];
  const childEnvironment = { ...process.env };
  if (key && fs.existsSync(key)) {
    args.push("-f", key);
    delete childEnvironment.TAURI_SIGNING_PRIVATE_KEY;
  }
  args.push(artifact);
  run("npx", args, { env: childEnvironment });
  requireRegularFile(
    `${artifact}.sig`,
    "Tauri updater signature for the host-signed artifact",
  );
}

function findLinuxAppImage() {
  return findSingleArtifact(
    path.join(root, "dist/linux-x64"),
    (file) => file.endsWith(".AppImage"),
    "CentralD Admin AppImage",
  );
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

/// Writes the Tauri updater configuration that must be baked into the Admin
/// binary: the public verification key and the manifest endpoints. The pubkey
/// and endpoints are public build metadata and are baked for every build
/// (native and container, signed and unsigned) so installed Admin apps can
/// always locate and verify updates. Tauri only generates its own `.sig`
/// updater artifacts when `--signed` is set, because producing those requires
/// the private signing key.
function createTauriReleaseConfig() {
  if (!buildConfig.tauriUpdaterPubkey.trim()) return "";
  const destination = path.join(
    root,
    "dist",
    `.tauri-release-config-${process.pid}.json`,
  );
  const value = {
    plugins: {
      updater: {
        pubkey: buildConfig.tauriUpdaterPubkey,
        endpoints: [tauriManifestUrl(buildConfig)],
      },
    },
  };
  if (options.signed) {
    value.bundle = { createUpdaterArtifacts: true };
  }
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
