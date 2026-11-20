import { useCallback, useEffect, useState } from "react";
import { api, type CreatedJoinToken, type JoinToken } from "../api";
import { ago, dateTime, nowSeconds } from "../format";
import { useLive, useLiveEvents } from "../live";
import { navigate } from "../router";
import {
  Badge,
  Button,
  Card,
  CopyBlock,
  Field,
  Link,
  Notice,
  PageHeader,
  errorText,
  useTick,
} from "../ui";

type Platform = "linux" | "windows" | "manual";

function isLoopback(address: string) {
  const host = address.replace(/:\d+$/, "");
  return host === "localhost" || host.startsWith("127.") || host === "[::1]";
}

export function AddDevice() {
  useTick();
  const [name, setName] = useState("");
  const [address, setAddress] = useState(window.location.host);
  const [monitorOnly, setMonitorOnly] = useState(false);
  const [hours, setHours] = useState(24);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<CreatedJoinToken | null>(null);
  const [platform, setPlatform] = useState<Platform>("linux");
  const [tokens, setTokens] = useState<JoinToken[]>([]);
  const { devices } = useLive();

  const loadTokens = useCallback(() => {
    api
      .joinTokens()
      .then(setTokens)
      .catch(() => {});
  }, []);
  useEffect(loadTokens, [loadTokens]);
  useLiveEvents((event) => {
    if (event.type === "join_tokens" || event.type === "resync") loadTokens();
  });

  const current = created ? tokens.find((t) => t.id === created.id) : undefined;
  const joined = current?.deviceId
    ? devices.find((d) => d.id === current.deviceId)
    : undefined;

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      setCreated(
        await api.createJoinToken({
          name,
          serverAddress: address,
          expiresInHours: hours,
          monitorOnly,
        }),
      );
      loadTokens();
    } catch (e) {
      setError(errorText(e));
    }
    setBusy(false);
  };

  return (
    <>
      <PageHeader
        title="Add a device"
        subtitle="Create a one-time join code, then run one command on the machine you want to manage."
      />
      <div className="grid grid-2">
        {!created ? (
          <Card title="1. Create a join code">
            <form className="form" onSubmit={create}>
              <Field
                label="Device name (optional)"
                hint="Defaults to the machine's hostname."
              >
                <input
                  type="text"
                  value={name}
                  maxLength={64}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="nas, pihole, gaming-pc…"
                />
              </Field>
              <Field
                label="Server address the device should connect to"
                hint="The address and port the new machine can reach this server at."
              >
                <input
                  type="text"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  spellCheck={false}
                  required
                />
              </Field>
              {isLoopback(address) && (
                <Notice tone="warn">
                  You opened CentralD on this server itself, so this address
                  only works here. Use the server's LAN address (for example{" "}
                  <code>192.168.1.10:7443</code>) so other machines can reach
                  it. The code also includes the server's other addresses as
                  fallbacks.
                </Notice>
              )}
              <fieldset
                className="stack"
                style={{ border: 0, padding: 0, margin: 0, gap: 8 }}
              >
                <legend className="field-label" style={{ marginBottom: 6 }}>
                  What can CentralD do on it?
                </legend>
                <label className="choice">
                  <input
                    type="radio"
                    name="mode"
                    checked={!monitorOnly}
                    onChange={() => setMonitorOnly(false)}
                  />
                  <span>
                    Full control
                    <small>
                      Health monitoring, commands, updates, reboots, and a
                      terminal.
                    </small>
                  </span>
                </label>
                <label className="choice">
                  <input
                    type="radio"
                    name="mode"
                    checked={monitorOnly}
                    onChange={() => setMonitorOnly(true)}
                  />
                  <span>
                    Monitor only
                    <small>
                      Reports health; the machine itself refuses every command
                      and terminal.
                    </small>
                  </span>
                </label>
              </fieldset>
              <Field label="Code expires after">
                <select
                  value={hours}
                  onChange={(e) => setHours(Number(e.target.value))}
                >
                  <option value={1}>1 hour</option>
                  <option value={24}>24 hours</option>
                  <option value={168}>7 days</option>
                </select>
              </Field>
              {error && <Notice tone="bad">{error}</Notice>}
              <Button variant="primary" type="submit" busy={busy}>
                Create join code
              </Button>
            </form>
          </Card>
        ) : (
          <Card
            title="2. Install the agent"
            actions={
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setCreated(null)}
              >
                Start over
              </Button>
            }
          >
            <div className="tabs" role="tablist">
              {(["linux", "windows", "manual"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  role="tab"
                  className="tab"
                  aria-selected={platform === p}
                  onClick={() => setPlatform(p)}
                >
                  {p === "linux"
                    ? "Linux"
                    : p === "windows"
                      ? "Windows"
                      : "Manual"}
                </button>
              ))}
            </div>
            {platform === "linux" && (
              <div className="stack" style={{ gap: 12 }}>
                <p style={{ margin: 0 }}>
                  On the machine, open a terminal and paste this. It works on
                  Debian, Ubuntu, Raspberry Pi OS, Fedora, and Arch, and asks
                  for your sudo password if needed.
                </p>
                <CopyBlock
                  label="Linux install command"
                  text={created.linuxCommand}
                />
              </div>
            )}
            {platform === "windows" && (
              <div className="stack" style={{ gap: 12 }}>
                <p style={{ margin: 0 }}>
                  Open <strong>PowerShell as Administrator</strong> (right-click
                  the Start button → Terminal (Admin)) and paste this.
                </p>
                <CopyBlock
                  label="Windows install command"
                  text={created.windowsCommand}
                />
              </div>
            )}
            {platform === "manual" && (
              <div className="stack" style={{ gap: 12 }}>
                <ol className="steps">
                  <li>
                    Install the <code>centrald-agent</code> package or binary
                    for the machine.
                  </li>
                  <li>
                    Run{" "}
                    <code>
                      sudo centrald-agent enroll
                      {monitorOnly ? " --monitor-only" : ""}
                    </code>{" "}
                    and paste this join code when asked:
                  </li>
                </ol>
                <CopyBlock label="Join code" text={created.code} />
              </div>
            )}
            <p className="muted" style={{ fontSize: "0.88rem" }}>
              The command checks this server's identity before downloading
              anything. The code works once and expires{" "}
              {dateTime(created.expiresAt)}.
            </p>
            {joined ? (
              <Notice tone="good">
                <strong>{joined.name}</strong> joined.{" "}
                <Link to={`/devices/${joined.id}`}>Open it</Link> or{" "}
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    setCreated(null);
                    setName("");
                  }}
                >
                  add another device
                </a>
                .
              </Notice>
            ) : (
              <Notice>
                <span className="row">
                  <span className="spinner" aria-hidden /> Waiting for the
                  device to connect…
                </span>
              </Notice>
            )}
          </Card>
        )}
        <Card title="Join codes">
          {tokens.length === 0 ? (
            <p className="muted">No recent join codes.</p>
          ) : (
            <ul className="list">
              {tokens.map((token) => {
                const expired = token.expiresAt <= nowSeconds();
                return (
                  <li key={token.id}>
                    <span>
                      <strong>{token.name || "Unnamed device"}</strong>
                      <span className="device-sub">
                        {" "}
                        · created {ago(token.createdAt)} by {token.createdBy}
                      </span>
                    </span>
                    <span className="row">
                      {token.usedAt ? (
                        token.deviceId ? (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              navigate(`/devices/${token.deviceId}`)
                            }
                          >
                            <Badge tone="good">Used</Badge>
                          </Button>
                        ) : (
                          <Badge tone="good">Used</Badge>
                        )
                      ) : expired ? (
                        <Badge>Expired</Badge>
                      ) : (
                        <>
                          <Badge tone="info">Waiting</Badge>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              api.revokeJoinToken(token.id).then(loadTokens)
                            }
                          >
                            Revoke
                          </Button>
                        </>
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
