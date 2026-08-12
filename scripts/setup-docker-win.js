import { commandExists, run } from "./command.js";

if (process.platform !== "win32") {
  throw new Error("setup:docker:win must run on Windows.");
}
if (!commandExists("docker", ["version"])) {
  throw new Error(
    "Docker Desktop is missing or stopped. Install with: winget install --id Docker.DockerDesktop --exact",
  );
}
run("docker", [
  "build",
  "--file",
  "docker/linux-builder.Dockerfile",
  "--tag",
  "centrald-linux-builder:ubuntu-24.04",
  ".",
]);
