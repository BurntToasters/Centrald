# Releases

How CentralD is built, packaged, signed, and verified.

## What a release contains

| File                                       | For                                  |
| ------------------------------------------ | ------------------------------------ |
| `centrald-server_<v>_{amd64,arm64}.deb`    | Debian, Ubuntu, Raspberry Pi OS      |
| `centrald-agent_<v>_{amd64,arm64}.deb`     | Managed Debian-family machines       |
| `centrald-{server,agent}-<v>-1.<arch>.rpm` | Fedora and other RPM distributions   |
| `centrald-<v>-linux-<arch>.tar.gz`         | Any Linux; also the Arch source      |
| `PKGBUILD`, `*.install`                    | Arch Linux (`makepkg -si`)           |
| `centrald-agent-<v>-windows-<arch>.exe`    | Windows agent, if installing by hand |
| `SHA256SUMS`, `SHA256SUMS.minisig`         | Verification                         |

Linux binaries are static (musl), so one build runs on every distribution. The
server packages include the agent builds for every platform, which is what the
web app's install commands download.

## Verifying a download

Every file is listed in `SHA256SUMS`, which is signed with this Minisign key:

```text
RWRNjmoIyXcnKU2YVT/YXlUwEjmsMgJpfPv6N1t9uTjBzlWy9xozbca8
```

```sh
minisign -Vm SHA256SUMS -P RWRNjmoIyXcnKU2YVT/YXlUwEjmsMgJpfPv6N1t9uTjBzlWy9xozbca8
sha256sum --ignore-missing -c SHA256SUMS
```

The key is also in `packaging/minisign.json`.

## Building from source

Requirements: Rust (stable, via `rustup`), Node.js 24.22.1+ or 26.13.0+ with npm
12+, and on Linux `musl-tools`, `dpkg-dev`, and optionally `rpm`.

```sh
npm ci
npm run build:web
rustup target add x86_64-unknown-linux-musl
CENTRALD_REQUIRE_UI=1 cargo build --release --locked \
  --target x86_64-unknown-linux-musl -p centrald-server -p centrald-agent
npm run package
```

Packages land in `dist/`. `npm run package` packages whatever builds exist under
`target/`; add `--require-all` to insist on every platform. Builds are
reproducible: archive timestamps come from the last commit
(`SOURCE_DATE_EPOCH`).

For development, `npm run dev:server` runs the server from source and
`npm run dev:web` serves the web app with live reload, proxying the API to
`https://127.0.0.1:7443`.

## Publishing a release

1. Set the version in `package.json`, the workspace `Cargo.toml`, and
   `Cargo.lock` (via `cargo update --workspace --offline`).
2. Commit, then push a tag `v<version>`.
3. The `Release` workflow builds Linux (x86_64 and ARM64, static musl) and the
   Windows agent (x86_64 and ARM64), packages everything, signs `SHA256SUMS`,
   and opens a **draft** GitHub release.
4. Review the draft and publish it.

The workflow needs two repository secrets: `MINISIGN_SECRET_KEY_B64` (the secret
key file, base64-encoded) and `MINISIGN_PASSWORD` (empty for an unencrypted
key).

## Dependency policy

- npm packages must be at least three days old (`min-release-age=3` in
  `.npmrc`).
- Cargo dependencies must be at least 72 hours old. Update them with
  `npm run deps:rust:update`, which resolves in a copy of the workspace and
  refuses younger crates. `npm run check:cargo-update-policy` keeps other
  scripts from calling `cargo update` directly.

## Continuous integration

Every pull request runs:

- formatting, ESLint, Clippy (`-D warnings`), and TypeScript checks;
- the Windows agent build and Clippy;
- the end-to-end suite (real server, agents, and Chromium), which uploads its
  report as the `e2e-report` artifact;
- the package smoke test: installs the `.deb` packages on the runner, completes
  setup, enrolls a machine with the web app's install command, runs a command,
  switches to the packaged agent, and purges everything.
