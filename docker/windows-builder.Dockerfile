# syntax=docker/dockerfile:1.7
# Windows builder for the CentralD client and Admin NSIS installers.
#
# The image builds BOTH windows targets (x64 and ARM64) at image-build time and
# leaves the artifacts in C:\src\dist\windows-x64 and C:\src\dist\windows-arm64.
# The host extracts them with `docker create` + `docker cp` and performs all
# Tauri/MinISign signing locally, so signing keys never enter the container.
#
# Requires a Docker engine running Windows containers (Docker Desktop in
# Windows-containers mode, or a Windows Server Docker engine).

FROM mcr.microsoft.com/windows/servercore:ltsc2022

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Node 22 LTS (pinned to the repository toolchain version).
ADD https://nodejs.org/dist/v22.16.0/node-v22.16.0-win-x64.zip C:\\node.zip
RUN Expand-Archive -Path C:\\node.zip -DestinationPath C:\\; Remove-Item C:\\node.zip
ENV PATH="C:\\node-v22.16.0-win-x64;${PATH}"

# Latest stable Rust toolchain via rustup. --no-modify-path keeps the registry
# PATH untouched; the cargo bin directory is appended explicitly above.
ADD https://win.rustup.rs/x86_64 C:\\rustup-init.exe
RUN C:\\rustup-init.exe -y --profile minimal --default-toolchain stable --default-host x86_64-pc-windows-msvc --no-modify-path; Remove-Item C:\\rustup-init.exe
ENV PATH="C:\\Users\\ContainerAdministrator\\.cargo\\bin;${PATH}"

# MSVC toolchain for x64 and ARM64 targets plus the matching Windows 10 SDK.
# This is the heavy layer (several GB); it is cached after the first build.
ADD https://aka.ms/vs/17/release/vs_BuildTools.exe C:\\vs_BuildTools.exe
RUN Start-Process -FilePath C:\\vs_BuildTools.exe -ArgumentList '--quiet','--wait','--norestart','--nocache','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.VC.Tools.ARM64','--add','Microsoft.VisualStudio.Component.Windows10SDK.20348' -Wait -NoNewWindow; Remove-Item C:\\vs_BuildTools.exe

WORKDIR C:\\src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts=false
COPY . .

# The project always builds on the latest stable Rust: refresh the toolchain
# even when rustup-init installed from a cached image layer.
RUN rustup update stable; rustup target add x86_64-pc-windows-msvc; rustup target add aarch64-pc-windows-msvc

# Unsigned builds: signing happens on the host after extraction so the private
# keys are never available inside the container.
RUN node scripts/build.js --target windows-x64
RUN node scripts/build.js --target windows-arm64
