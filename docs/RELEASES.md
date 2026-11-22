# Releases

How CentralD is built, packaged, signed, and verified.

## What a release contains

| File                                       | For                                  |
| ------------------------------------------ | ------------------------------------ |
| `centrald-server_<v>_{amd64,arm64}.deb`    | Debian, Ubuntu, Raspberry Pi OS      |
| `centrald-agent_<v>_{amd64,arm64}.deb`     | Managed Debian-family machines       |
| `centrald-{server,agent}-<v>-1.<arch>.rpm` | Fedora and other RPM distributions   |
| `centrald-<v>-linux-<arch>.tar.gz`         | Any Linux; also the Arch source      |
| `PKGBUILD`, `centrald-*.install`           | Arch Linux (`makepkg -si`)           |
| `centrald-agent-<v>-windows-<arch>.exe`    | Windows agent, if installing by hand |
| `SHA256SUMS`, `SHA256SUMS.minisig`         | Verification                         |

Linux binaries are static (musl), so one build runs on every distribution. The
server packages include the agent builds for every platform, which is what the
web app's install commands download. Every package also carries
`THIRD-PARTY-NOTICES.txt`, the licences of the Rust crates and web packages
compiled in.

A prerelease such as `0.2.0-rc.1` keeps that version in its file names; inside
the packages it is `0.2.0~rc.1` (deb, rpm) and `0.2.0rc.1` (pacman), so the
final `0.2.0` upgrades it.

## Verifying a download

Every file of the release is listed in `SHA256SUMS` under the name it is
published with. `SHA256SUMS` is signed with this Minisign key:

```text
RWRNjmoIyXcnKU2YVT/YXlUwEjmsMgJpfPv6N1t9uTjBzlWy9xozbca8
```

```sh
minisign -Vm SHA256SUMS -P RWRNjmoIyXcnKU2YVT/YXlUwEjmsMgJpfPv6N1t9uTjBzlWy9xozbca8
# Check the files you downloaded, by name, so a missing file is an error:
grep -E '  (centrald-server_0.2.0_amd64.deb|centrald-agent_0.2.0_amd64.deb)$' SHA256SUMS |
  sha256sum --strict -c
```

With every file downloaded, `sha256sum --strict -c SHA256SUMS` checks them all.
Do not use `--ignore-missing`: it passes when a file you meant to check is not
there. On Arch, check `PKGBUILD`, `centrald-server.install`, and
`centrald-agent.install` this way before `makepkg`; the `PKGBUILD` pins the
tarball's checksum, and the `.install` files run as root.

The key is also in `packaging/minisign.json`.

Each agent build is also signed on its own. The signature's trusted comment is
`centrald-agent <version> <os>-<arch>` (for example
`centrald-agent 0.2.0 linux-aarch64`), and server packages ship it next to the
agent as `centrald-agent-<os>-<arch>[.exe].minisig`. `centrald-agent update`
refuses a build unless this signature verifies against the key built into the
agent, names its own platform, and names a newer version. A server without the
`.minisig` files (for example one installed from hand-built binaries) cannot
update agents.

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

Packages land in `dist/` (flat: the file names are the release asset names).
`npm run package` packages whatever builds exist under `target/`; add
`--require-all` to insist on every platform and on a `.minisig` for every agent.
It refuses to run when `package.json` and `Cargo.toml` disagree on the version,
or without git history unless `SOURCE_DATE_EPOCH` is set.

Builds aim to be reproducible: archive and package timestamps come from the last
commit (`SOURCE_DATE_EPOCH`), the embedded web files carry no timestamps, file
modes do not depend on your umask, and RPMs record the build host as `centrald`.
To reproduce a release byte for byte, use the same Rust version as the release
build and the same `CARGO_HOME` path (`~/.cargo` on the runner): the binaries
contain paths of crate sources under it.

For development, `npm run dev:server` runs the server from source and
`npm run dev:web` serves the web app with live reload, proxying the API to
`https://127.0.0.1:7443`.

## Publishing a release

1. Set the version in `package.json` and the workspace `Cargo.toml`, then
   refresh the workspace entries in `Cargo.lock` with
   `cargo metadata --offline --format-version 1 > /dev/null` (it changes no
   dependency).
2. Optional: run the `Release` workflow by hand (**Actions > Release > Run
   workflow**). This dry run builds, signs with a throwaway key, and keeps the
   packages as the `release-dry-run` artifact; it publishes nothing.
3. Commit, then push a tag `v<version>`.
4. The `Release` workflow first checks that the tag, `package.json`,
   `Cargo.toml`, and `Cargo.lock` agree. It then builds Linux (x86_64 and ARM64,
   static musl) and the Windows agent (x86_64 and ARM64), signs each agent
   build, packages everything, signs `SHA256SUMS`, checks that every listed file
   is uploaded under its listed name, and opens a **draft** GitHub release.
   Re-running a failed run replaces the files of the existing draft.
5. Review the draft and publish it.

The workflow needs two repository secrets: `MINISIGN_SECRET_KEY_B64` (the secret
key file, base64-encoded) and `MINISIGN_PASSWORD` (empty for an unencrypted
key). Never set `CENTRALD_UPDATE_PUBKEY` for a release build: it replaces the
update key built into the agent and exists for development and E2E only.

## Dependency policy

- npm packages must be at least three days old (`min-release-age=3` in
  `.npmrc`).
- Older npm versions ignore that setting, so `.npmrc` also sets
  `engine-strict=true`: npm refuses to run with a Node or npm older than
  `package.json` `engines`.
- Cargo dependencies must be at least 72 hours old. Update them with
  `npm run deps:rust:update`, which resolves in a copy of the workspace and
  refuses younger crates; pass `-p <crate>` to update only some crates when
  others are too new. CI enforces the rule on the result:
  `node scripts/check-cargo-update-policy.mjs --base <commit>` compares
  `Cargo.lock` with the base commit and fails if any new crate version is
  younger than 72 hours or comes from git, whichever command produced it.
  Without `--base` it checks uncommitted changes.
- `rust-version` in `Cargo.toml` is the oldest Rust that builds CentralD. The
  workspace uses resolver 3, which prefers dependency versions that support it,
  and CI builds with exactly that version.
- Known vulnerabilities fail the `Advisories` workflow (`cargo audit`, and
  `npm audit` for the root and the site), which also runs weekly.

## Continuous integration

Every pull request runs:

- formatting, ESLint, Clippy (`-D warnings`), and TypeScript checks;
- the Cargo dependency-age check, a build with the minimum Rust version, and the
  docs site check and build (`npm run site:install` first);
- `cargo audit` and `npm audit`;
- the Windows agent build and Clippy;
- the end-to-end suite (real server, agents, and Chromium), which uploads its
  report as the `e2e-report` artifact;
- the package smoke test: installs the `.deb` packages on the runner, completes
  setup, enrolls the server's own machine with the web app's install command,
  runs a command, restarts the server, lets the agent package take over, repairs
  a broken `/etc/centrald`, checks remove/reinstall and a disabled service
  across an upgrade, and purges everything.
