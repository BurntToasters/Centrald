import { Channel, invoke } from "@tauri-apps/api/core";
import {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

type AdminUpdateStatus = Readonly<{
  available: boolean;
  version: string | null;
}>;

type ServerProfile = Readonly<{
  id: string;
  identityId: string;
  name: string;
  endpoint: string;
  serverName: string;
  certificateExpiresAt: string;
}>;

type ProfileWarning = Readonly<{
  directory: string;
  message: string;
}>;

type ProfileList = Readonly<{
  profiles: readonly ServerProfile[];
  warnings: readonly ProfileWarning[];
}>;

type Target = Readonly<{
  id: string;
  name: string;
  os: string;
  architecture: string;
  version: string;
  lastSeen: string;
  online: boolean;
  server: boolean;
}>;

type Invitation = Readonly<{
  id: string;
  accessKey: string;
  expiresAt: string;
}>;

type EnrollmentKey = Readonly<{
  id: string;
  name: string;
  role: string;
  createdAt: string;
  expiresAt: string;
  consumedAt: string;
  revokedAt: string;
  revokedReason: string;
  status: "pending" | "consumed" | "revoked" | "expired" | string;
}>;

type Job = Readonly<{
  id: string;
  targetId: string;
  kind: string;
  state: number;
  expiresAt: string;
}>;

type ServerSettings = {
  revision: string;
  instanceId: string;
  publicHost: string;
  enrollmentListen: string;
  clientListen: string;
  adminListen: string;
  databaseMaxConnections: number;
  heartbeatIntervalSeconds: number;
  offlineAfterSeconds: number;
  jobTtlSeconds: number;
  shellIdleTimeoutSeconds: number;
  maxShellFrameBytes: number;
  updatesEnabled: boolean;
  updateChannel: string;
  updateManifestUrl: string;
  updateCheckIntervalSeconds: number;
  updateAllowPrerelease: boolean;
  dataDir: string;
  localSocket: string;
  databaseUrlEnv: string;
  databaseEnvironmentFile: string;
  rootCertPath: string;
  localOnlyFields: string[];
  restartRequired: boolean;
  updateLatestVersion: string;
  updateAvailable: boolean;
};

type EnrollmentForm = {
  accessKey: string;
  connectionOverride: string;
};

type ElevationChallenge = Readonly<{
  id: string;
  nonce: string;
  contextHash: string;
  expiresAt: string;
  challengeSignature: string;
}>;

type ShellOpenResult = Readonly<{
  handle: string;
}>;

type ShellEvent =
  | Readonly<{ type: "data"; sessionId: string; data: string }>
  | Readonly<{
      type: "close";
      sessionId: string;
      reason: string;
      exitCode: number;
    }>
  | Readonly<{ type: "error"; message: string }>;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

type Section = "overview" | "devices" | "terminal" | "settings";

// These paths are compiled only as hardening scaffolds in this alpha. Keep the
// operator surface fail-closed until the complete privileged execution and
// terminal acceptance suites are release gates.
const PRIVILEGED_CLIENT_OPERATIONS_AVAILABLE = false;
const TERMINAL_FEATURE_AVAILABLE = false;

const emptyEnrollment: EnrollmentForm = {
  accessKey: "",
  connectionOverride: "",
};

const sectionLabels: ReadonlyArray<Readonly<[Section, string]>> = [
  ["overview", "Overview"],
  ["devices", "Devices"],
  ["terminal", "Terminal"],
  ["settings", "Server settings"],
];

export function App() {
  const [profiles, setProfiles] = useState<readonly ServerProfile[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [targets, setTargets] = useState<readonly Target[]>([]);
  const [clientInvitations, setClientInvitations] = useState<
    readonly EnrollmentKey[]
  >([]);
  const [settings, setSettings] = useState<ServerSettings | null>(null);
  const [section, setSection] = useState<Section>("overview");
  const [showEnrollment, setShowEnrollment] = useState(false);
  const [showInvitation, setShowInvitation] = useState(false);
  const [enrollment, setEnrollment] = useState(emptyEnrollment);
  const [inviteName, setInviteName] = useState("");
  const [inviteLifetime, setInviteLifetime] = useState(900);
  const [invitation, setInvitation] = useState<Invitation | null>(null);
  const [terminalTarget, setTerminalTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadingTargets, setLoadingTargets] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [availableUpdate, setAvailableUpdate] =
    useState<AdminUpdateStatus | null>(null);
  const [checkingUpdate, setCheckingUpdate] = useState(false);

  const selected =
    profiles.find((profile) => profile.id === selectedId) ?? null;
  const onlineTargets = useMemo(
    () => targets.filter((target) => target.online),
    [targets],
  );

  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    void invoke<ProfileList>("list_profiles")
      .then((loaded) => {
        setProfiles(loaded.profiles);
        if (loaded.profiles.length > 0) setSelectedId(loaded.profiles[0].id);
        if (loaded.warnings.length > 0) {
          const details = loaded.warnings
            .slice(0, 3)
            .map((warning) => `${warning.directory}: ${warning.message}`)
            .join("; ");
          setNotice(
            `Skipped ${loaded.warnings.length} damaged Admin profile${loaded.warnings.length === 1 ? "" : "s"}. ${details}`,
          );
        }
      })
      .catch((reason: unknown) => setError(String(reason)));
  }, []);

  const refreshClientInvitations = useCallback(async (profileId: string) => {
    try {
      setClientInvitations(
        await invoke<EnrollmentKey[]>("list_client_invitations", {
          profileId,
          includeInactive: false,
        }),
      );
    } catch (reason) {
      setError(String(reason));
    }
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    void loadTargets(selectedId);
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) return;
    void invoke<EnrollmentKey[]>("list_client_invitations", {
      profileId: selectedId,
      includeInactive: false,
    })
      .then(setClientInvitations)
      .catch((reason: unknown) => setError(String(reason)));
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) return;
    void loadSettings(selectedId);
  }, [section, selectedId]);

  async function loadTargets(profileId: string) {
    setLoadingTargets(true);
    setError(null);
    try {
      const loaded = await invoke<Target[]>("list_targets", { profileId });
      setTargets(loaded);
      setTerminalTarget((current) => current || loaded[0]?.id || "");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoadingTargets(false);
    }
  }

  async function loadSettings(profileId: string) {
    setError(null);
    try {
      setSettings(
        await invoke<ServerSettings>("get_server_settings", { profileId }),
      );
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function refreshTargets() {
    if (!selectedId) return;
    await loadTargets(selectedId);
  }

  async function submitEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const profile = await invoke<ServerProfile>("enroll_admin", {
        input: {
          accessKey: enrollment.accessKey.trim(),
          connectionOverride: enrollment.connectionOverride.trim() || undefined,
        },
      });
      setProfiles((current) => [...current, profile]);
      setSelectedId(profile.id);
      setEnrollment(emptyEnrollment);
      setShowEnrollment(false);
      setNotice(`Connected to ${profile.name} with a local mTLS identity.`);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function submitInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedId) return;
    setBusy(true);
    setError(null);
    try {
      const created = await invoke<Invitation>("create_client_invitation", {
        profileId: selectedId,
        name: inviteName.trim(),
        expiresInSeconds: inviteLifetime,
      });
      setInvitation(created);
      await refreshClientInvitations(selectedId);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function queueJob(
    target: Target,
    kind: string,
    label: string,
    confirmMessage?: string,
    parameters?: Record<string, unknown>,
  ) {
    if (!selectedId) return;
    if (confirmMessage && !window.confirm(confirmMessage)) return;
    setBusy(true);
    setError(null);
    try {
      const job = await invoke<Job>("start_job", {
        profileId: selectedId,
        targetId: target.id,
        kind,
        reason: `${label} requested from CentralD Admin`,
        parametersJson: JSON.stringify(parameters ?? {}),
      });
      setNotice(`${label} queued for ${target.name}. Job ${job.id}.`);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function revokeTarget(target: Target) {
    if (!selectedId) return;
    const reason = window.prompt(
      `Reason for revoking ${target.name}:`,
      "Device retired from this CentralD server",
    );
    if (!reason?.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await invoke<string>("revoke_client", {
        profileId: selectedId,
        clientId: target.id,
        reason: reason.trim(),
      });
      setTargets((current) =>
        current.filter((candidate) => candidate.id !== target.id),
      );
      setNotice(`${target.name} was revoked.`);
    } catch (reasonValue) {
      setError(String(reasonValue));
    } finally {
      setBusy(false);
    }
  }

  async function revokeInvitation(invitationToRevoke: EnrollmentKey) {
    if (!selectedId || invitationToRevoke.status !== "pending") return;
    const reason = window.prompt(
      `Reason for revoking the invitation for ${invitationToRevoke.name}:`,
      "Invitation no longer needed",
    );
    if (!reason?.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await invoke<string>("revoke_client_invitation", {
        profileId: selectedId,
        invitationId: invitationToRevoke.id,
        reason: reason.trim(),
      });
      await refreshClientInvitations(selectedId);
      setNotice(`Invitation for ${invitationToRevoke.name} was revoked.`);
    } catch (reasonValue) {
      setError(String(reasonValue));
    } finally {
      setBusy(false);
    }
  }

  async function saveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedId || !settings) return;
    const portError = listenerPortError(settings);
    if (portError) {
      setError(portError);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const saved = await invoke<ServerSettings>("update_server_settings", {
        profileId: selectedId,
        settings,
      });
      setSettings(saved);
      setNotice(
        "Settings saved. Restart centrald-server from the host to apply them.",
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function checkForAdminUpdate() {
    setCheckingUpdate(true);
    setError(null);
    try {
      const status = await invoke<AdminUpdateStatus>("check_admin_update");
      setAvailableUpdate(status.available ? status : null);
      setNotice(
        status.available && status.version
          ? `CentralD Admin ${status.version} is available.`
          : "CentralD Admin is up to date.",
      );
    } catch (reason) {
      setError(
        `Admin update check failed. Signed release builds must include an updater endpoint and public key. ${String(reason)}`,
      );
    } finally {
      setCheckingUpdate(false);
    }
  }

  async function installAdminUpdate() {
    if (!availableUpdate) return;
    if (
      !window.confirm(
        `Download and install CentralD Admin ${availableUpdate.version ?? ""}? The application may close during installation.`,
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await invoke("install_admin_update");
      setNotice(
        "The signed update was installed. Reopen CentralD Admin to run the new version.",
      );
      setAvailableUpdate(null);
    } catch (reason) {
      setError(`Admin update installation failed: ${String(reason)}`);
    } finally {
      setBusy(false);
    }
  }

  function patchSettings(patch: Partial<ServerSettings>) {
    setSettings((current) => (current ? { ...current, ...patch } : current));
  }

  function selectProfile(profileId: string) {
    setTargets([]);
    setClientInvitations([]);
    setSettings(null);
    setError(null);
    setNotice(null);
    closeInvitation();
    closeEnrollment();
    setSelectedId(profileId);
    setSection("overview");
  }

  function closeEnrollment() {
    setEnrollment(emptyEnrollment);
    setShowEnrollment(false);
  }

  function closeInvitation() {
    setShowInvitation(false);
    setInviteName("");
    setInviteLifetime(900);
    setInvitation(null);
  }

  async function copyInvitation() {
    if (!invitation) return;
    try {
      await navigator.clipboard.writeText(invitation.accessKey);
      setNotice(
        "Client invitation copied. Treat it like a password until used. Clear your clipboard after enrollment; apps cannot reliably erase clipboard history.",
      );
    } catch {
      setError(
        "Clipboard access was denied. Select and copy the key manually.",
      );
    }
  }

  useEffect(() => {
    return () => {
      setInvitation(null);
      setEnrollment(emptyEnrollment);
    };
  }, []);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">
            C
          </span>
          <div>
            <p className="eyebrow">Homelab control plane</p>
            <h1>CentralD</h1>
          </div>
        </div>

        <div className="sidebar-group">
          <p className="sidebar-label">Servers</p>
          <div className="profile-list" aria-label="Server profiles">
            {profiles.map((profile) => (
              <button
                className={`profile ${profile.id === selectedId ? "selected" : ""}`}
                key={profile.id}
                onClick={() => selectProfile(profile.id)}
                type="button"
              >
                <span className="profile-dot" aria-hidden="true" />
                <span>
                  <strong>{profile.name}</strong>
                  <small>{profile.serverName}</small>
                </span>
              </button>
            ))}
          </div>
          <button
            className="button secondary full-width"
            onClick={() => setShowEnrollment(true)}
            type="button"
          >
            Add server
          </button>
        </div>

        <nav className="section-nav" aria-label="Administration sections">
          {sectionLabels.map(([value, label]) => (
            <button
              className={section === value ? "active" : ""}
              disabled={
                !selected ||
                (value === "terminal" && !TERMINAL_FEATURE_AVAILABLE)
              }
              key={value}
              onClick={() => setSection(value)}
              title={
                value === "terminal" && !TERMINAL_FEATURE_AVAILABLE
                  ? "Terminal is unavailable in this alpha release."
                  : undefined
              }
              type="button"
            >
              <span className="nav-glyph" aria-hidden="true">
                {label.slice(0, 1)}
              </span>
              {label}
            </button>
          ))}
        </nav>

        <div className="sidebar-security">
          <span className="lock-dot" aria-hidden="true" />
          Admin traffic uses mutual TLS. Access keys are consumed once and are
          never stored.
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">{selected?.endpoint ?? "Not connected"}</p>
            <h2>{selected?.name ?? "CentralD Admin"}</h2>
          </div>
          {selected && (
            <div className="topbar-actions">
              <span className="secure-pill">mTLS verified</span>
              {availableUpdate ? (
                <button
                  className="button primary"
                  disabled={busy}
                  onClick={() => void installAdminUpdate()}
                  type="button"
                >
                  Install {availableUpdate.version}
                </button>
              ) : (
                <button
                  className="button ghost"
                  disabled={checkingUpdate}
                  onClick={() => void checkForAdminUpdate()}
                  type="button"
                >
                  {checkingUpdate ? "Checking update" : "Check app update"}
                </button>
              )}
              <button
                className="button ghost"
                disabled={loadingTargets}
                onClick={() => void refreshTargets()}
                type="button"
              >
                {loadingTargets ? "Refreshing" : "Refresh"}
              </button>
            </div>
          )}
        </header>

        {error && (
          <div className="banner error" role="alert">
            <strong>Action failed</strong>
            <span>{error}</span>
            <button onClick={() => setError(null)} type="button">
              Dismiss
            </button>
          </div>
        )}
        {notice && (
          <div className="banner notice" role="status">
            <strong>Done</strong>
            <span>{notice}</span>
            <button onClick={() => setNotice(null)} type="button">
              Dismiss
            </button>
          </div>
        )}

        {!selected ? (
          <div className="empty-state">
            <span className="empty-mark">CD</span>
            <p className="eyebrow">One-paste onboarding</p>
            <h2>No server profile</h2>
            <p>
              After <code>centrald-server initial-setup</code> (or{" "}
              <code>centrald-server config</code>), paste the one-time Admin
              access key here. CentralD establishes trust and generates the
              Admin certificate locally.
            </p>
            <button
              className="button primary"
              onClick={() => setShowEnrollment(true)}
              type="button"
            >
              Enroll this Admin
            </button>
          </div>
        ) : (
          <div className="page-content">
            <GettingStarted />
            {section === "overview" && (
              <Overview
                invitationCount={clientInvitations.length}
                onCreateInvitation={() => setShowInvitation(true)}
                onOpenDevices={() => setSection("devices")}
                onlineCount={onlineTargets.length}
                targets={targets}
              />
            )}

            {section === "devices" && (
              <Devices
                busy={busy}
                invitations={clientInvitations}
                loading={loadingTargets}
                latestVersion={settings?.updateLatestVersion ?? ""}
                onCreateInvitation={() => setShowInvitation(true)}
                onJob={queueJob}
                onRevoke={revokeTarget}
                onRevokeInvitation={revokeInvitation}
                targets={targets}
                updatesEnabled={settings?.updatesEnabled ?? false}
              />
            )}

            {section === "terminal" && (
              <TerminalPanel
                profileId={selectedId}
                selectedTarget={terminalTarget}
                targets={targets}
                onTargetChange={setTerminalTarget}
              />
            )}

            {section === "settings" && (
              <SettingsPanel
                busy={busy}
                onPatch={patchSettings}
                onSave={saveSettings}
                settings={settings}
              />
            )}
          </div>
        )}
      </section>

      {showEnrollment && (
        <div className="modal-backdrop">
          <form className="modal enrollment" onSubmit={submitEnrollment}>
            <div className="modal-heading">
              <div>
                <p className="eyebrow">One-paste secure onboarding</p>
                <h2>Add a CentralD server</h2>
              </div>
              <button
                aria-label="Close"
                className="icon-button"
                onClick={closeEnrollment}
                type="button"
              >
                x
              </button>
            </div>
            <label>
              Admin access key
              <textarea
                autoComplete="off"
                onChange={(event) =>
                  setEnrollment((current) => ({
                    ...current,
                    accessKey: event.target.value,
                  }))
                }
                placeholder="centrald-invite1..."
                required
                rows={4}
                spellCheck={false}
                value={enrollment.accessKey}
              />
              <small>
                The self-contained key carries authenticated public trust
                metadata and is consumed on first successful enrollment.
              </small>
            </label>
            <label>
              Connection host or IP <span className="optional">Optional</span>
              <input
                onChange={(event) =>
                  setEnrollment((current) => ({
                    ...current,
                    connectionOverride: event.target.value,
                  }))
                }
                placeholder="192.168.1.20"
                value={enrollment.connectionOverride}
              />
              <small>
                Use this only when the invitation TLS name does not resolve from
                this computer.
              </small>
            </label>
            <p className="security-note">
              The invitation is never saved. CentralD generates a local mTLS
              identity and stores its private key with operating-system user
              permissions.
            </p>
            <div className="modal-actions">
              <button
                className="button secondary"
                disabled={busy}
                onClick={closeEnrollment}
                type="button"
              >
                Cancel
              </button>
              <button className="button primary" disabled={busy} type="submit">
                {busy ? "Enrolling" : "Enroll securely"}
              </button>
            </div>
          </form>
        </div>
      )}

      {showInvitation && (
        <div className="modal-backdrop">
          <form className="modal invitation-modal" onSubmit={submitInvitation}>
            <div className="modal-heading">
              <div>
                <p className="eyebrow">Client enrollment</p>
                <h2>Create a one-time invitation</h2>
              </div>
              <button
                aria-label="Close"
                className="icon-button"
                onClick={closeInvitation}
                type="button"
              >
                x
              </button>
            </div>
            {!invitation ? (
              <>
                <label>
                  Device name
                  <input
                    maxLength={128}
                    onChange={(event) => setInviteName(event.target.value)}
                    placeholder="lab-workstation"
                    required
                    value={inviteName}
                  />
                </label>
                <label>
                  Invitation lifetime
                  <select
                    onChange={(event) =>
                      setInviteLifetime(Number(event.target.value))
                    }
                    value={inviteLifetime}
                  >
                    <option value={300}>5 minutes</option>
                    <option value={900}>15 minutes</option>
                    <option value={3600}>1 hour</option>
                    <option value={86400}>24 hours</option>
                  </select>
                </label>
                <p className="security-note">
                  The client needs only this invitation and, when DNS is
                  unavailable, the server IP or FQDN.
                </p>
                <div className="modal-actions">
                  <button
                    className="button secondary"
                    onClick={closeInvitation}
                    type="button"
                  >
                    Cancel
                  </button>
                  <button
                    className="button primary"
                    disabled={busy}
                    type="submit"
                  >
                    {busy ? "Creating" : "Create invitation"}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="success-block">
                  <strong>Invitation ready</strong>
                  <span>Expires {invitation.expiresAt}</span>
                </div>
                <label>
                  One-time client invitation
                  <textarea
                    readOnly
                    rows={7}
                    spellCheck={false}
                    value={invitation.accessKey}
                  />
                </label>
                <p className="security-note warning">
                  This is the only time the invitation is displayed. Copy it
                  before closing this dialog.
                </p>
                <div className="modal-actions">
                  <button
                    className="button secondary"
                    onClick={closeInvitation}
                    type="button"
                  >
                    Done
                  </button>
                  <button
                    className="button primary"
                    onClick={() => void copyInvitation()}
                    type="button"
                  >
                    Copy invitation
                  </button>
                </div>
              </>
            )}
          </form>
        </div>
      )}
    </main>
  );
}

function Overview({
  invitationCount,
  onCreateInvitation,
  onOpenDevices,
  onlineCount,
  targets,
}: Readonly<{
  invitationCount: number;
  onCreateInvitation: () => void;
  onOpenDevices: () => void;
  onlineCount: number;
  targets: readonly Target[];
}>) {
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">At a glance</p>
          <h3>Homelab overview</h3>
          <p>Inventory, enrollment, and server health in one place.</p>
        </div>
        <button
          className="button primary"
          onClick={onCreateInvitation}
          type="button"
        >
          Enroll a device
        </button>
      </div>
      <div className="metric-grid">
        <article className="metric-card">
          <span>Managed devices</span>
          <strong>{targets.length}</strong>
          <small>Active identities</small>
        </article>
        <article className="metric-card">
          <span>Online now</span>
          <strong>{onlineCount}</strong>
          <small>Within the offline threshold</small>
        </article>
        <article className="metric-card">
          <span>Needs attention</span>
          <strong>{targets.length - onlineCount}</strong>
          <small>Offline or not yet checked in</small>
        </article>
        <article className="metric-card">
          <span>Pending invitations</span>
          <strong>{invitationCount}</strong>
          <small>Revocable until consumed or expired</small>
        </article>
      </div>
      <div className="overview-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Fleet status</p>
              <h4>Recent devices</h4>
            </div>
            <button
              className="text-button"
              onClick={onOpenDevices}
              type="button"
            >
              View all
            </button>
          </div>
          {targets.length === 0 ? (
            <div className="panel-empty">
              No clients are enrolled yet. Create an invitation to add the first
              one.
            </div>
          ) : (
            <div className="compact-device-list">
              {targets.slice(0, 6).map((target) => (
                <div key={target.id}>
                  <span
                    className={`status-dot ${target.online ? "online" : "offline"}`}
                  />
                  <span>
                    <strong>{target.name}</strong>
                    <small>
                      {target.os} / {target.architecture}
                    </small>
                  </span>
                  <span className="muted">
                    {target.version || "Unknown version"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
        <section className="panel posture-panel">
          <p className="eyebrow">Security posture</p>
          <h4>Trust is pinned at enrollment</h4>
          <ul className="check-list">
            <li>One-time Argon2id-backed invitations</li>
            <li>Separate client and Admin mTLS identities</li>
            <li>Server-local Admin lifecycle and destructive reset</li>
            <li>Pinned TLS names and role-specific mTLS issuers</li>
          </ul>
        </section>
      </div>
    </>
  );
}

function GettingStarted() {
  return (
    <details className="getting-started" open>
      <summary>Getting started and common tasks</summary>
      <div className="getting-started-grid">
        <div>
          <strong>1. Add this server</strong>
          <span>
            Paste the Admin access key from <code>initial-setup</code> or{" "}
            <code>centrald-server config</code> into Add server.
          </span>
        </div>
        <div>
          <strong>2. Add a device</strong>
          <span>
            Create a client invitation here or in the server TUI, then run{" "}
            <code>centrald-client enroll</code> on the device.
          </span>
        </div>
        <div>
          <strong>3. Confirm health</strong>
          <span>
            Use Overview and Devices to confirm enrolled clients are online and
            reporting inventory.
          </span>
        </div>
        <div>
          <strong>Advanced controls</strong>
          <span>
            Routine settings are available here. PKI, database secrets, Admin
            lifecycle, update origin, and destructive reset stay server-local.
          </span>
        </div>
      </div>
    </details>
  );
}

function Devices({
  busy,
  invitations,
  latestVersion,
  loading,
  onCreateInvitation,
  onJob,
  onRevoke,
  onRevokeInvitation,
  targets,
  updatesEnabled,
}: Readonly<{
  busy: boolean;
  invitations: readonly EnrollmentKey[];
  latestVersion: string;
  loading: boolean;
  onCreateInvitation: () => void;
  onJob: (
    target: Target,
    kind: string,
    label: string,
    confirmMessage?: string,
    parameters?: Record<string, unknown>,
  ) => Promise<void>;
  onRevoke: (target: Target) => Promise<void>;
  onRevokeInvitation: (invitation: EnrollmentKey) => Promise<void>;
  targets: readonly Target[];
  updatesEnabled: boolean;
}>) {
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Managed endpoints</p>
          <h3>Devices</h3>
          <p>
            Inventory and enrollment are active. Typed maintenance jobs stay
            unavailable in this alpha until the complete privileged execution
            path is a release gate.
          </p>
        </div>
        <button
          className="button primary"
          onClick={onCreateInvitation}
          type="button"
        >
          New invitation
        </button>
      </div>
      <section className="panel device-panel">
        {loading ? (
          <div className="panel-empty">Loading device inventory...</div>
        ) : targets.length === 0 ? (
          <div className="panel-empty">No enrolled clients reported.</div>
        ) : (
          <div
            className="device-table"
            role="table"
            aria-label="Managed devices"
          >
            <div className="device-row table-head" role="row">
              <span>Device</span>
              <span>Platform</span>
              <span>Last seen</span>
              <span>Status</span>
              <span>Actions</span>
            </div>
            {targets.map((target) => (
              <div className="device-row" key={target.id} role="row">
                <span className="device-name">
                  <span
                    className={`status-dot ${target.online ? "online" : "offline"}`}
                  />
                  <span>
                    <strong>{target.name}</strong>
                    <small>CentralD {target.version || "unknown"}</small>
                  </span>
                </span>
                <span>
                  {target.os} / {target.architecture}
                </span>
                <span>{target.lastSeen}</span>
                <span>
                  <span
                    className={`status-pill ${target.online ? "online" : "offline"}`}
                  >
                    {target.online ? "Online" : "Offline"}
                  </span>
                </span>
                <span className="row-actions">
                  {PRIVILEGED_CLIENT_OPERATIONS_AVAILABLE ? (
                    <>
                      <button
                        disabled={busy}
                        title="Unavailable in this alpha release."
                        onClick={() =>
                          void onJob(
                            target,
                            "restart-client-service",
                            "Client service restart",
                          )
                        }
                        type="button"
                      >
                        Restart agent
                      </button>
                      <button
                        disabled={busy}
                        title="Unavailable in this alpha release."
                        onClick={() =>
                          void onJob(
                            target,
                            "check-os-updates",
                            "OS update check",
                          )
                        }
                        type="button"
                      >
                        Check updates
                      </button>
                      <button
                        disabled={busy}
                        title="Unavailable in this alpha release."
                        onClick={() =>
                          void onJob(
                            target,
                            "apply-os-updates",
                            "Apply OS updates",
                            `Apply all available OS package updates on ${target.name}?`,
                          )
                        }
                        type="button"
                      >
                        Apply updates
                      </button>
                      <button
                        disabled={busy || !updatesEnabled || !latestVersion}
                        title={
                          updatesEnabled
                            ? "Installs the server-verified CentralD release on this device."
                            : "Release updates are disabled on this server."
                        }
                        onClick={() => {
                          const version = window.prompt(
                            `Approved CentralD version to install on ${target.name}:`,
                            latestVersion,
                          );
                          if (!version?.trim()) return;
                          void onJob(
                            target,
                            "update-client",
                            "CentralD client update",
                            `Install CentralD ${version.trim()} on ${target.name}?`,
                            { expectedVersion: version.trim() },
                          );
                        }}
                        type="button"
                      >
                        Update CentralD
                      </button>
                    </>
                  ) : null}
                  <button
                    className="danger-text"
                    disabled={busy}
                    onClick={() => void onRevoke(target)}
                    type="button"
                  >
                    Revoke
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
      <section className="panel device-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Enrollment access</p>
            <h4>Pending client invitations</h4>
          </div>
        </div>
        {invitations.length === 0 ? (
          <div className="panel-empty">No pending client invitations.</div>
        ) : (
          <div
            className="invitation-table"
            role="table"
            aria-label="Pending client invitations"
          >
            <div className="invitation-row table-head" role="row">
              <span>Name</span>
              <span>Created</span>
              <span>Expires</span>
              <span>Status</span>
              <span>Actions</span>
            </div>
            {invitations.map((entry) => (
              <div className="invitation-row" key={entry.id} role="row">
                <span>
                  <strong>{entry.name}</strong>
                  <small>{entry.id}</small>
                </span>
                <span>{entry.createdAt}</span>
                <span>{entry.expiresAt}</span>
                <span>
                  <span className={`status-pill ${entry.status}`}>
                    {entry.status}
                  </span>
                </span>
                <span className="row-actions">
                  <button
                    className="danger-text"
                    disabled={busy || entry.status !== "pending"}
                    onClick={() => void onRevokeInvitation(entry)}
                    type="button"
                  >
                    Revoke
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

function TerminalPanel({
  onTargetChange,
  profileId,
  selectedTarget,
  targets,
}: Readonly<{
  onTargetChange: (value: string) => void;
  profileId: string | null;
  selectedTarget: string;
  targets: readonly Target[];
}>) {
  const [privilege, setPrivilege] = useState<"low" | "elevated">("low");
  const [accountUser, setAccountUser] = useState("");
  const [accountPassword, setAccountPassword] = useState("");
  const [saveCredentials, setSaveCredentials] = useState(false);
  const [opening, setOpening] = useState(false);
  const [terminalStatus, setTerminalStatus] = useState<string | null>(null);
  const [sessionOpen, setSessionOpen] = useState(false);
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const sessionRef = useRef<{ handle: string; terminal: Terminal } | null>(
    null,
  );
  const fitAddonRef = useRef<FitAddon | null>(null);

  const terminalReady = Boolean(
    TERMINAL_FEATURE_AVAILABLE && profileId && selectedTarget,
  );

  async function openTerminal() {
    if (!profileId || !selectedTarget) return;
    setOpening(true);
    setTerminalStatus("opening secure terminal...");
    try {
      const columns = fitAddonRef.current
        ? Math.max(
            2,
            Math.min(500, fitAddonRef.current.proposeDimensions()?.cols ?? 80),
          )
        : 80;
      const rows = fitAddonRef.current
        ? Math.max(
            2,
            Math.min(500, fitAddonRef.current.proposeDimensions()?.rows ?? 24),
          )
        : 24;
      let challengeId = "";
      let challengeSignature = "";
      if (privilege === "elevated") {
        const challenge = await invoke<ElevationChallenge>("begin_elevation", {
          profileId,
          targetId: selectedTarget,
          operation: "open_shell",
          reason: "operator requested an elevated terminal",
        });
        challengeId = challenge.id;
        challengeSignature = challenge.challengeSignature;
      }
      const channel = new Channel<ShellEvent>();
      const { handle } = await invoke<ShellOpenResult>("open_shell", {
        profileId,
        targetId: selectedTarget,
        privilege,
        columns,
        rows,
        reason: "operator requested a terminal",
        accountUser,
        accountPassword,
        saveCredentials,
        challengeId,
        challengeSignature,
        channel,
      });
      if (sessionRef.current) {
        sessionRef.current.terminal.dispose();
        sessionRef.current = null;
      }
      const terminal = new Terminal({
        cursorBlink: true,
        convertEol: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        fontSize: 13,
        scrollback: 5000,
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      fitAddonRef.current = fitAddon;
      if (terminalRef.current) {
        terminal.open(terminalRef.current);
        fitAddon.fit();
      }
      sessionRef.current = { handle, terminal };
      setSessionOpen(true);
      terminal.onData((data) => {
        void invoke("shell_input", {
          handle,
          data: bytesToBase64(new TextEncoder().encode(data)),
        }).catch((error: unknown) => {
          setTerminalStatus(String(error));
        });
      });
      terminal.onResize(({ cols, rows: newRows }) => {
        void invoke("shell_resize", {
          handle,
          columns: cols,
          rows: newRows,
        }).catch((error: unknown) => {
          setTerminalStatus(String(error));
        });
      });
      channel.onmessage = (event) => {
        if (event.type === "data") {
          const bytes = base64ToBytes(event.data);
          terminal.write(bytes);
        } else if (event.type === "close") {
          setSessionOpen(false);
          setTerminalStatus(`Session closed: ${event.reason || "ended"}`);
        } else if (event.type === "error") {
          setSessionOpen(false);
          setTerminalStatus(`Session error: ${event.message}`);
        }
      };
      setTerminalStatus("secure terminal connected");
    } catch (error) {
      setTerminalStatus(String(error));
    } finally {
      setOpening(false);
    }
  }

  function closeTerminal() {
    const session = sessionRef.current;
    if (!session) return;
    void invoke("shell_close", { handle: session.handle }).catch(
      () => undefined,
    );
    session.terminal.dispose();
    sessionRef.current = null;
    setSessionOpen(false);
    setTerminalStatus("terminal closed");
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Interactive access</p>
          <h3>Terminal</h3>
          <p>
            Unavailable in this alpha release. PTY/ConPTY and credential-vault
            code remains security scaffolding until the complete privileged
            execution path passes release acceptance testing.
          </p>
        </div>
      </div>
      <div className="terminal-layout">
        <section className="panel terminal-connect">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Session setup</p>
              <h4>Open a managed terminal</h4>
            </div>
          </div>
          <label>
            Target
            <select
              disabled={!TERMINAL_FEATURE_AVAILABLE}
              onChange={(event) => onTargetChange(event.target.value)}
              value={selectedTarget}
            >
              <option value="">Select a device</option>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.os})
                </option>
              ))}
            </select>
          </label>
          <label>
            Privilege
            <select
              disabled={!TERMINAL_FEATURE_AVAILABLE}
              onChange={(event) =>
                setPrivilege(
                  event.target.value === "elevated" ? "elevated" : "low",
                )
              }
              value={privilege}
            >
              <option value="low">Low (managed service account)</option>
              <option value="elevated">Elevated (root / SYSTEM)</option>
            </select>
          </label>
          <label>
            OS account
            <input
              autoComplete="off"
              disabled={!TERMINAL_FEATURE_AVAILABLE}
              onChange={(event) => setAccountUser(event.target.value)}
              placeholder={privilege === "elevated" ? "root" : "centrald"}
              value={accountUser}
            />
          </label>
          <label>
            OS account password
            <input
              autoComplete="off"
              disabled={!TERMINAL_FEATURE_AVAILABLE}
              onChange={(event) => setAccountPassword(event.target.value)}
              type="password"
              value={accountPassword}
            />
          </label>
          <label className="checkbox-row">
            <input
              checked={saveCredentials}
              disabled={!TERMINAL_FEATURE_AVAILABLE}
              onChange={(event) => setSaveCredentials(event.target.checked)}
              type="checkbox"
            />
            Save the validated credentials in this machine's OS vault
          </label>
          <div className="row-actions">
            <button
              className="button primary"
              disabled={!terminalReady || opening}
              onClick={
                TERMINAL_FEATURE_AVAILABLE
                  ? () => void openTerminal()
                  : undefined
              }
              type="button"
            >
              {opening ? "Opening..." : "Open terminal"}
            </button>
            <button
              disabled={!sessionOpen}
              onClick={closeTerminal}
              type="button"
            >
              Close terminal
            </button>
          </div>
          <p className="form-help">
            Terminal execution and credential saving are intentionally disabled
            in this alpha.
          </p>
          {terminalStatus ? (
            <p className="terminal-status">{terminalStatus}</p>
          ) : null}
        </section>
        <section className="terminal-window" aria-label="Secure terminal">
          <div className="terminal-chrome">
            <span />
            <span />
            <span />
            <strong>centrald secure terminal</strong>
          </div>
          <div className="terminal-body" ref={terminalRef}>
            <p className="terminal-muted">
              Open a session to connect the xterm view to the remote PTY.
            </p>
          </div>
        </section>
      </div>
    </>
  );
}

function SettingsPanel({
  busy,
  onPatch,
  onSave,
  settings,
}: Readonly<{
  busy: boolean;
  onPatch: (patch: Partial<ServerSettings>) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  settings: ServerSettings | null;
}>) {
  if (!settings) {
    return <div className="panel panel-empty">Loading server settings...</div>;
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Configuration parity</p>
          <h3>Server settings</h3>
          <p>
            Remote-safe settings are editable. Trust, secrets, Admin access, and
            destructive operations stay on the server console.
          </p>
        </div>
        <span className="revision">
          Revision {settings.revision.slice(0, 10)}
        </span>
      </div>
      <form className="settings-stack" onSubmit={(event) => void onSave(event)}>
        {settings.restartRequired && (
          <div className="banner warning-banner">
            <strong>Restart required</strong>
            <span>
              Saved settings are waiting for centrald-server to restart.
            </span>
          </div>
        )}
        <section className="panel settings-section">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Network</p>
              <h4>TLS listeners</h4>
            </div>
          </div>
          <div className="field-grid three">
            <label>
              Enrollment listener
              <input
                onChange={(event) =>
                  onPatch({ enrollmentListen: event.target.value })
                }
                required
                value={settings.enrollmentListen}
              />
            </label>
            <label>
              Client listener
              <input
                onChange={(event) =>
                  onPatch({ clientListen: event.target.value })
                }
                required
                value={settings.clientListen}
              />
            </label>
            <label>
              Admin listener
              <input
                onChange={(event) =>
                  onPatch({ adminListen: event.target.value })
                }
                required
                value={settings.adminListen}
              />
            </label>
          </div>
          <p className="form-help">
            Listener ports must be 1024-65535. The packaged server deliberately
            runs without privileged bind capabilities.
          </p>
          <div className="field-grid two read-only-grid">
            <label>
              Public TLS name
              <input readOnly value={settings.publicHost} />
              <small>Rotate this only from centrald-server config.</small>
            </label>
            <label>
              Server instance ID
              <input readOnly value={settings.instanceId} />
            </label>
          </div>
        </section>

        <section className="panel settings-section">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Runtime</p>
              <h4>Heartbeat, jobs, and shell limits</h4>
            </div>
          </div>
          <div className="field-grid three">
            <NumberField
              label="Heartbeat seconds"
              min={5}
              value={settings.heartbeatIntervalSeconds}
              onChange={(value) => onPatch({ heartbeatIntervalSeconds: value })}
            />
            <NumberField
              label="Offline after seconds"
              min={6}
              value={settings.offlineAfterSeconds}
              onChange={(value) => onPatch({ offlineAfterSeconds: value })}
            />
            <NumberField
              label="Job TTL seconds"
              min={60}
              value={settings.jobTtlSeconds}
              onChange={(value) => onPatch({ jobTtlSeconds: value })}
            />
            <NumberField
              label="Database pool size"
              min={1}
              value={settings.databaseMaxConnections}
              onChange={(value) => onPatch({ databaseMaxConnections: value })}
            />
            <NumberField
              help="Closes a shell session after this long without input or output."
              label="Shell idle timeout"
              min={30}
              value={settings.shellIdleTimeoutSeconds}
              onChange={(value) => onPatch({ shellIdleTimeoutSeconds: value })}
            />
            <NumberField
              help="Per-frame terminal byte limit enforced by the server and broker."
              label="Max shell frame bytes"
              min={1024}
              value={settings.maxShellFrameBytes}
              onChange={(value) => onPatch({ maxShellFrameBytes: value })}
            />
          </div>
        </section>

        <section className="panel settings-section">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Updates</p>
              <h4>Release feed</h4>
            </div>
            <label className="switch-row">
              <input
                checked={settings.updatesEnabled}
                onChange={(event) =>
                  onPatch({ updatesEnabled: event.target.checked })
                }
                type="checkbox"
              />
              Check for updates
            </label>
          </div>
          <div className="field-grid two">
            <label>
              Channel
              <input
                disabled
                readOnly
                title="The release channel changes the trusted update feed and is server-local-only."
                value={settings.updateChannel}
              />
              <span className="field-hint">
                Change the release channel from centrald-server config on the
                server.
              </span>
            </label>
            <NumberField
              label="Check interval seconds"
              min={300}
              value={settings.updateCheckIntervalSeconds}
              onChange={(value) =>
                onPatch({ updateCheckIntervalSeconds: value })
              }
            />
          </div>
          <label>
            Manifest URL
            <input
              disabled
              readOnly
              required={settings.updatesEnabled}
              title="The release manifest origin is server-local-only to prevent remote request pivots."
              type="url"
              value={settings.updateManifestUrl}
            />
            <span className="field-hint">
              Change the manifest origin from centrald-server config on the
              server.
            </span>
          </label>
          {settings.updateLatestVersion ? (
            <p className="field-hint">
              Latest verified release: CentralD {settings.updateLatestVersion}
              {settings.updateAvailable
                ? " (newer than this server)"
                : " (matches this server)"}
              . Client package installation stays unavailable in this alpha.
            </p>
          ) : (
            <p className="field-hint">
              No release manifest has been verified yet; client package
              installation stays unavailable in this alpha.
            </p>
          )}
          <label className="checkbox-row">
            <input
              checked={settings.updateAllowPrerelease}
              disabled
              title="The prerelease flag is server-local-only. Change the release channel from centrald-server config or centrald-server channel."
              type="checkbox"
            />
            Allow prerelease versions
          </label>
        </section>

        <section className="panel settings-section local-only">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Server-local</p>
              <h4>Protected paths and secret sources</h4>
            </div>
            <span className="status-pill protected">Console only</span>
          </div>
          <div className="read-only-list">
            <div>
              <span>Data directory</span>
              <code>{settings.dataDir}</code>
            </div>
            <div>
              <span>Local control socket</span>
              <code>{settings.localSocket}</code>
            </div>
            <div>
              <span>Database URL environment variable</span>
              <code>{settings.databaseUrlEnv}</code>
            </div>
            <div>
              <span>Database environment file</span>
              <code>{settings.databaseEnvironmentFile}</code>
            </div>
            <div>
              <span>Root certificate</span>
              <code>{settings.rootCertPath}</code>
            </div>
          </div>
        </section>

        <div className="settings-actions">
          <p>
            Saving uses revision checks and preserves a private backup of the
            previous TOML file.
          </p>
          <button className="button primary" disabled={busy} type="submit">
            {busy ? "Saving" : "Save settings"}
          </button>
        </div>
      </form>
    </>
  );
}

function NumberField({
  disabled = false,
  help,
  label,
  min,
  onChange,
  value,
}: Readonly<{
  disabled?: boolean;
  help?: string;
  label: string;
  min: number;
  onChange: (value: number) => void;
  value: number;
}>) {
  return (
    <label>
      {label}
      <input
        disabled={disabled}
        min={min}
        onChange={(event) => onChange(Number(event.target.value))}
        readOnly={disabled}
        required={!disabled}
        type="number"
        value={value}
      />
      {help ? <small>{help}</small> : null}
    </label>
  );
}

function listenerPortError(settings: ServerSettings): string | null {
  const listeners = [
    ["Enrollment", settings.enrollmentListen],
    ["Client", settings.clientListen],
    ["Admin", settings.adminListen],
  ] as const;
  const ports: number[] = [];
  for (const [label, value] of listeners) {
    const host = value.trim();
    const separator = host.lastIndexOf(":");
    if (separator <= 0 || separator === host.length - 1) {
      return `${label} listener must look like 0.0.0.0:7443 (ports 1024-65535).`;
    }
    const port = Number(host.slice(separator + 1));
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      return `${label} listener port must be between 1024 and 65535. The packaged server cannot bind privileged ports.`;
    }
    ports.push(port);
  }
  if (new Set(ports).size !== ports.length) {
    return "Enrollment, client, and Admin listeners must use distinct ports.";
  }
  return null;
}
