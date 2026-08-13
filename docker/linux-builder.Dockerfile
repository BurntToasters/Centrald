# syntax=docker/dockerfile:1.7
FROM node:22.16.0-bookworm-slim AS node-toolchain
# The project requires npm >= 12.0.1; the Node 22 base image ships npm 10.
RUN npm install -g npm@12.0.2
FROM rust:bookworm AS rust-toolchain

FROM ubuntu:24.04 AS builder
ARG DEBIAN_FRONTEND=noninteractive
# The release channel is public build metadata. CENTRALD_RELEASE_CHANNEL is
# read by centrald-common's build.rs and baked into every binary; it must
# never carry secrets.
ARG CENTRALD_RELEASE_CHANNEL=
ENV CENTRALD_RELEASE_CHANNEL=${CENTRALD_RELEASE_CHANNEL}

COPY --from=node-toolchain /usr/local/ /usr/local/
COPY --from=rust-toolchain /usr/local/cargo/ /usr/local/cargo/
COPY --from=rust-toolchain /usr/local/rustup/ /usr/local/rustup/
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CI=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      desktop-file-utils \
      dpkg-dev \
      file \
      libayatana-appindicator3-dev \
      libssl-dev \
      libwebkit2gtk-4.1-dev \
      librsvg2-dev \
      patchelf \
      pkg-config \
      protobuf-compiler \
      wget \
      xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY package.json package-lock.json .npmrc ./
# Install scripts are allowed inside the builder image; the allowlist lives in
# package.json (allowScripts). The project .npmrc enforces min-release-age=3.
RUN npm ci --ignore-scripts=false
COPY . .

# The project always builds on the latest stable Rust: refresh the toolchain
# even when the floating `rust:bookworm` base image was cached locally.
RUN rustup update stable \
    && rustup target add x86_64-unknown-linux-gnu \
    && cargo build --locked --release --target x86_64-unknown-linux-gnu \
      -p centrald-server -p centrald-client \
    && cd apps/admin \
    && npx tauri build \
      --target x86_64-unknown-linux-gnu \
      --bundles appimage \
    && cd ../.. \
    && node scripts/package-linux.js \
      --target-dir target/x86_64-unknown-linux-gnu/release \
      --output dist/linux-x64

FROM scratch AS export
COPY --from=builder /src/dist/linux-x64/ /
