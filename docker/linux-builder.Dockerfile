# syntax=docker/dockerfile:1.7
FROM node:22.22.2-bookworm-slim AS node-toolchain
# The project requires npm >= 12.0.1; the Node 22 base image ships npm 10.
# Install into a separate prefix so npm never overwrites its running files.
RUN npm install -g --prefix /usr/local/npm-latest npm@latest
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
    PATH=/usr/local/npm-latest/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CI=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      desktop-file-utils \
      dpkg-dev \
      file \
      libayatana-appindicator3-dev \
      libclang-dev \
      libpam0g-dev \
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
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    rustup update stable \
    && rustup target add x86_64-unknown-linux-gnu \
    && if [ -n "$CENTRALD_RELEASE_CHANNEL" ]; then \
         node scripts/build.js --target linux-x64 --native --channel "$CENTRALD_RELEASE_CHANNEL"; \
       else \
         node scripts/build.js --target linux-x64 --native; \
       fi

FROM scratch AS export
COPY --from=builder /src/dist/linux-x64/ /
