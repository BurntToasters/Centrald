# CentralD

CentralD is a security-first homelab device manager for Windows and Linux. One
Ubuntu Server host manages outbound-only clients through a Tauri desktop Admin
application.

The repository is pre-release and intentionally uses one clean configuration,
database, enrollment, and update model. **There is no legacy-key or schema
migration path.** Development installs created before this redesign should be
reset with the destructive command documented below.

Current version: `0.1.0-alpha.1`.

Documentation lives at <https://centrald.dev>; the rendered pages are generated
from the `docs/` directory by the Astro site in [`site/`](site/).

## Target platforms

| Component | Supported build targets                                            |
| --------- | ------------------------------------------------------------------ |
| Server    | Ubuntu Server 24.04 x86_64; Ubuntu Server 26.04 x86_64 is a target |
| Client    | Linux x86_64, Windows x86_64, Windows ARM64                        |
| Admin     | Linux x86_64 AppImage, Windows x86_64/ARM64 NSIS                   |
| Database  | PostgreSQL                                                         |

CentralD is intended for private LAN or VPN deployment. Do not expose an alpha
server directly to the public Internet.

## Five-minute quick start

For the normal packaged Ubuntu Server install, the entire first-run path is:

```text
sudo centrald-server initial-setup
sudo centrald-server config
# on each managed Linux device
sudo centrald-client enroll
```

`initial-setup` creates the database, PKI, and first Admin access key. On a
normal systemd package installation it also enables and starts
`centrald-server.service`. The TUI puts routine enrollment and health tasks
first; network, database, PKI, and storage controls remain available under
clearly marked advanced menus. See [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
for the novice walkthrough.

## End-to-end setup

### 1. Initialize the server

Install the server package, PostgreSQL, and then run:

```text
sudo centrald-server initial-setup
```

The recommended wizard can provision a dedicated local PostgreSQL role/database
automatically; an existing or remote PostgreSQL URL remains available under the
advanced path. The generated service login never receives database-creation or
role-management privileges; a destination-pinned local postgres administrator
creates its one owned database. Setup refuses to adopt a non-empty
`/var/lib/centrald` data root. It validates the host, database, paths, and
listeners before writing anything. It creates the database schema, an offline
root recovery bundle, role-specific online issuers, the server identity, and the
first one-time Admin access key.

Non-interactive setup remains available for automation:

```text
sudo CENTRALD_DATABASE_URL='postgresql://...' \
  centrald-server initial-setup \
  --non-interactive \
  --public-host centrald.home.arpa \
  --admin-name owner \
  --recovery-key-output /root/centrald-offline-root.pem
```

The database URL is written to the configured root-only environment file. It is
never stored in `centrald.config` or printed by the management console. The
target database name must not already exist: setup creates a dedicated database
and binds both its PostgreSQL comment and an internal installation marker to the
new CentralD server instance.

### 2. Configure and administer the server locally

```text
sudo centrald-server config
```

The local guided console works even when the daemon is stopped. It provides all
persisted settings and local-only security operations, including:

- listener, timing, update policy, database-pool, and audit settings;
- package-managed fixed security paths for configuration, database secrets, PKI,
  runtime state, and sockets;
- safe server TLS-name rotation and guided online-issuer rotation using the
  offline root recovery bundle;
- client invitations, Admin access keys, identity listing, and revocation;
- health and diagnostic summaries.

Admin identity creation, rotation, revocation, PKI paths, database secret
location, and destructive reset remain server-local by design. The desktop app
can manage clients and non-secret runtime settings, but it cannot make itself an
Admin or change these trust anchors.

On a normal packaged systemd installation, `initial-setup` enables and starts
the service automatically. If setup reports that service startup was skipped or
failed, run:

```text
sudo systemctl enable --now centrald-server
# source/container fallback
sudo centrald-server run
```

### 3. Enroll a client

Create a client invitation in `centrald-server config` or from an enrolled Admin
app. On the client run:

```text
sudo centrald-client enroll
```

Paste the invitation and accept or replace the suggested server IP/FQDN. No CA
file, port, certificate, or additional flag is required. The invitation carries
the exact public root CA, TLS name, service ports, role, identity name, and
expiry. A connection override changes only the TCP destination; TLS still
verifies the name and CA embedded in the invitation.

Invitations are bearer secrets: deliver them over a trusted channel. They expire
within 24 hours, are stored only as Argon2id hashes on the server, and are
consumed transactionally once. For automation on Unix, use an absolute,
root-owned, private `--key-file`; on every platform, a secret manager may use
piped `--key-stdin`. These automation forms use the server embedded in the
invitation unless `--server` is explicitly supplied, so they do not stop for a
second prompt. CentralD intentionally does not accept invitation values in
process arguments.

The Linux package creates an unprivileged `centrald` service account. Client
identity data is stored only under `/var/lib/centrald-client`, separate from
server state. Successful enrollment publishes `current.pointer` and
enables/starts the client service; `rescue --repair` never trusts a
configuration-provided repair root.

### 4. Enroll the Admin app

Open CentralD Admin and paste the one-time Admin access key produced by setup or
`centrald-server config`. The app generates its mTLS key locally, uses the
embedded CA to enroll, and stores only the resulting profile. The one-time
access key is not retained. Privileged shell keys will be registered only when
the brokered terminal subsystem is implemented.

The Admin app renews its mTLS identity before expiry and currently provides:

- basic server/client identity, platform, version, health, and last-seen
  inventory;
- one-time client invitation creation;
- client and pending client-invitation revocation;
- revision-checked server settings with restart-required reporting;
- clear local-only boundaries for trust and Admin lifecycle settings;
- an explicit, signed Tauri self-update flow that requires operator approval and
  verifies the updater JSON with Minisign before the Tauri plugin runs.

Typed job submission and the interactive terminal stay unavailable in this
alpha. See [Implementation status](docs/IMPLEMENTATION_STATUS.md).

## Destructive reset

The exact reset command is:

```text
sudo centrald-server --nuke --yes-i-want-to-do-this
```

It serializes setup/reset activity, acquires the daemon runtime lock, preflights
every filesystem target, verifies the instance-bound data/environment markers,
PostgreSQL database comment and installation row, and any managed local role
marker, then drops only those owned objects. A durable reset journal makes the
operation retryable after a database drop, role-removal failure, or partial
filesystem cleanup. Rerun the exact command to resume. The separately stored
offline root recovery bundle is intentionally preserved.

This command is the supported way to reset pre-release installations. There is
no compatibility parser for old enrollment keys and no database migration from
the abandoned pre-release model.

## Tracked build configuration

[`centrald.config`](centrald.config) is a tracked, non-secret `KEY=value` file
used by Rust builds and release tooling. Supported keys are:

- `REPO_URL`: source repository and default release origin;
- `UPDATE_BASE_URL`: optional mutable channel-feed directory;
- `ARTIFACT_BASE_URL_TEMPLATE`: immutable versioned artifact directory;
- `CDN_BASE_URL`: optional CDN base hosting the mutable channel manifests
  (`<CDN_BASE_URL>/<channel>` for every channel);
- `RELEASE_CHANNEL`: optional explicit channel (`alpha`, `beta`, `stable` —
  these are the only channels CentralD serves); when blank, the channel is
  auto-detected from the package version (no prerelease suffix = stable,
  otherwise the prerelease identifier). Override per build with `--channel` or
  `CENTRALD_RELEASE_CHANNEL`;
- `RELEASE_MANIFEST`: shared server/client release manifest filename;
- `TAURI_UPDATE_MANIFEST`: desktop updater manifest filename;
- `TAURI_UPDATER_PUBKEY`: public Tauri updater key;
- `MINISIGN_PUBLIC_KEY`: public Minisign verification key.

Private keys, database URLs, API tokens, and passwords are rejected as unknown
keys and must never be added to this file.

GitHub defaults use immutable artifacts under `/releases/download/v<version>/`.
Stable manifests are read from `/releases/latest/download/`; non-stable GitHub
channels use one atomic commit on the mutable `centrald-channels` branch through
`raw.githubusercontent.com`. Channel publication is monotonic by Semantic
Versioning and refuses same-version byte replacement.
`npm run release:publish-channel` retries by downloading and verifying the exact
manifests already attached to the immutable version release, not by regenerating
them. Generic HTTPS/S3-compatible origins can provide equivalent
`/<channel>/latest/` and versioned layouts.

## Development and release

```text
npm run setup
npm run config:check
npm run qa
```

Useful native build commands:

```text
npm run build:linux:x64:native
npm run build:win:x64
npm run build:win:arm64
```

The Ubuntu 24.04 Docker builder provides a reproducible unsigned Linux build.
Signed releases run as native Linux and Windows jobs so Tauri signing secrets
are never sent as Docker build arguments. Every distributable receives a
Minisign `.minisig`; Admin AppImage/NSIS artifacts additionally receive Tauri
`.sig` files. Version releases are created as drafts, verified, and published
once without asset replacement. The release manifest references only immutable
artifact and Minisign URLs.

See [Operations](docs/OPERATIONS.md), [Releases](docs/RELEASES.md), and
[Architecture](docs/ARCHITECTURE.md).

## Release workflow

Copy `.env.example` to `.env` and set the signing keys and publish gates, then:

```text
npm run release
```

On a Windows host this builds Windows x64/ARM64 with the host toolchain and
Linux x64 through Docker, signs everything, creates and pushes the `v<version>`
tag, uploads the GitHub release, and publishes channel manifests. Use
`npm run release -- --all-docker` only to opt into Windows-container builds. See
[Releases](docs/RELEASES.md) for key generation and the step-by-step flow.

## Documentation site

The `site/` folder is a static Astro 7 site deployed to Cloudflare Pages at
<https://centrald.dev>. It renders the repository `docs/` (and `SECURITY.md`)
into a navigable documentation site.

```text
npm run site:dev    # local development server
npm run site:check  # astro check (types + templates)
npm run site:build  # sync docs and produce site/dist
```

Cloudflare Pages is configured with root directory `site`, build command
`npm ci && npm run build`, and output directory `dist`. Set the Pages
`NODE_VERSION` environment variable to `22.22.2` (Astro 7 requires Node 22.12+).
The build always re-syncs `docs/*.md` into `site/src/content/docs` first, so
`docs/` remains the single source of truth; the sync output is gitignored.

## License

GPL-3.0-or-later.
