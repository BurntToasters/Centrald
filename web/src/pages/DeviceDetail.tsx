import { useCallback, useEffect, useState } from "react";
import {
  api,
  type ActionName,
  type Device,
  type MetricPoint,
  type Run,
} from "../api";
import {
  actionLabels,
  ago,
  bytes,
  dateTime,
  duration,
  osLabel,
  percent,
  short,
  stateLabels,
  stateTones,
} from "../format";
import { useDevice, useLive, useLiveEvents } from "../live";
import { navigate } from "../router";
import {
  Badge,
  Button,
  Card,
  Confirm,
  Empty,
  Link,
  Meter,
  Modal,
  Notice,
  PageHeader,
  StatusDot,
  errorText,
  useTick,
} from "../ui";

export function DeviceDetail({ id }: { id: string }) {
  useTick();
  const { loaded } = useLive();
  const device = useDevice(id);
  const [runs, setRuns] = useState<Run[]>([]);
  const [metrics, setMetrics] = useState<MetricPoint[]>([]);
  const [confirm, setConfirm] = useState<ActionName | "remove" | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [error, setError] = useState("");

  const loadRuns = useCallback(() => {
    api
      .runs({ deviceId: id, limit: 10 })
      .then(setRuns)
      .catch(() => {});
  }, [id]);

  useEffect(() => {
    loadRuns();
    api
      .metrics(id)
      .then(setMetrics)
      .catch(() => {});
    const timer = window.setInterval(() => {
      api
        .metrics(id)
        .then(setMetrics)
        .catch(() => {});
    }, 60000);
    return () => window.clearInterval(timer);
  }, [id, loadRuns]);

  useLiveEvents((event) => {
    if (
      event.type === "run" &&
      event.run.targets.some((t) => t.deviceId === id)
    ) {
      loadRuns();
    }
  });

  if (!device) {
    return loaded ? (
      <Card>
        <Empty
          title="Device not found"
          action={
            <Button onClick={() => navigate("/")}>Back to devices</Button>
          }
        >
          It may have been removed.
        </Empty>
      </Card>
    ) : null;
  }

  const status = device.status;
  const canCommand = device.online && device.allowCommands;
  const startAction = async (action: ActionName) => {
    const run = await api.startRun({
      deviceIds: [id],
      action,
      timeoutSeconds: action === "updates_apply" ? 3600 : 600,
    });
    navigate(`/runs/${run.id}`);
  };

  return (
    <>
      <PageHeader
        back={{ to: "/", label: "Devices" }}
        title={
          <span className="row" style={{ gap: 12 }}>
            <StatusDot online={device.online} />
            {device.name}
          </span>
        }
        subtitle={
          device.online
            ? `${osLabel(device)} · online`
            : `${osLabel(device)} · offline, last seen ${ago(device.lastSeenAt)}`
        }
        actions={
          <>
            <Button
              variant="primary"
              disabled={!canCommand}
              onClick={() => navigate(`/devices/${id}/terminal`)}
            >
              Open terminal
            </Button>
            <Button
              disabled={!canCommand}
              onClick={() => navigate(`/run?devices=${id}`)}
            >
              Run command
            </Button>
          </>
        }
      />
      {!device.allowCommands && (
        <div style={{ marginBottom: 16 }}>
          <Notice>
            This device was enrolled as <strong>monitor-only</strong>. It
            reports its health but refuses commands, actions, and terminals.
          </Notice>
        </div>
      )}
      {error && (
        <div style={{ marginBottom: 16 }}>
          <Notice tone="bad">{error}</Notice>
        </div>
      )}
      <div className="grid grid-2">
        <Card title="Resources">
          {status && device.online ? (
            <div className="stack" style={{ gap: 12 }}>
              <Meter
                label={`CPU (${status.cpuCount} cores)`}
                value={status.cpuPercent}
                detail={`${Math.round(status.cpuPercent)}%${status.load ? ` · load ${status.load[0].toFixed(2)}` : ""}`}
              />
              <Meter
                label="Memory"
                value={percent(
                  status.memory.usedBytes,
                  status.memory.totalBytes,
                )}
                detail={`${bytes(status.memory.usedBytes)} of ${bytes(status.memory.totalBytes)}`}
              />
              {status.swap.totalBytes > 0 && (
                <Meter
                  label="Swap"
                  value={percent(status.swap.usedBytes, status.swap.totalBytes)}
                  detail={`${bytes(status.swap.usedBytes)} of ${bytes(status.swap.totalBytes)}`}
                />
              )}
              {status.disks.map((disk) => (
                <Meter
                  key={disk.mount}
                  label={`Disk ${disk.mount}`}
                  value={percent(disk.usedBytes, disk.totalBytes)}
                  detail={`${bytes(disk.usedBytes)} of ${bytes(disk.totalBytes)}`}
                />
              ))}
            </div>
          ) : (
            <p className="muted">
              Live resource usage appears while the device is online.
            </p>
          )}
        </Card>
        <Card title="Health">
          <HealthPanel device={device} />
          <div className="row" style={{ marginTop: 16 }}>
            <Button
              size="sm"
              disabled={!canCommand}
              onClick={() => setConfirm("updates_check")}
            >
              Check for updates
            </Button>
            <Button
              size="sm"
              disabled={!canCommand}
              onClick={() => setConfirm("updates_apply")}
            >
              Install updates
            </Button>
            <Button
              size="sm"
              disabled={!canCommand}
              onClick={() => setConfirm("reboot")}
            >
              Reboot
            </Button>
          </div>
        </Card>
        <Card title="Last 24 hours">
          <Chart points={metrics} />
        </Card>
        <Card
          title="System"
          actions={
            <Button size="sm" variant="ghost" onClick={() => setRenaming(true)}>
              Rename
            </Button>
          }
        >
          <dl className="facts">
            <dt>Hostname</dt>
            <dd>{device.hostname || "—"}</dd>
            <dt>Operating system</dt>
            <dd>{osLabel(device)}</dd>
            <dt>Kernel</dt>
            <dd>{device.os.kernel || "—"}</dd>
            <dt>Architecture</dt>
            <dd>{device.os.arch || "—"}</dd>
            <dt>Uptime</dt>
            <dd>
              {status && device.online ? duration(status.uptimeSeconds) : "—"}
            </dd>
            <dt>Addresses</dt>
            <dd className="mono">{status?.addresses.join(", ") || "—"}</dd>
            <dt>Agent</dt>
            <dd>
              {device.agentVersion}
              {device.packageManaged ? " (package)" : ""}
            </dd>
            <dt>Enrolled</dt>
            <dd>{dateTime(device.enrolledAt)}</dd>
            <dt>Connected from</dt>
            <dd className="mono">{device.lastAddress || "—"}</dd>
          </dl>
        </Card>
      </div>
      <div style={{ marginTop: 16 }}>
        <Card
          title="Recent commands"
          actions={<Link to={`/runs`}>All history</Link>}
        >
          {runs.length === 0 ? (
            <p className="muted">Nothing has been run on this device yet.</p>
          ) : (
            <ul className="list">
              {runs.map((run) => {
                const target = run.targets.find((t) => t.deviceId === id);
                return (
                  <li key={run.id}>
                    <Link to={`/runs/${run.id}`} className="mono">
                      {run.kind === "action"
                        ? (actionLabels[run.command] ?? run.command)
                        : run.command}
                    </Link>
                    <span className="row">
                      {target && (
                        <Badge tone={stateTones[target.state]}>
                          {stateLabels[target.state]}
                          {target.exitCode !== null && target.state === "failed"
                            ? ` (${target.exitCode})`
                            : ""}
                        </Badge>
                      )}
                      <span className="muted nowrap">{ago(run.createdAt)}</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
      <div style={{ marginTop: 16 }}>
        <Card title="Danger zone">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <span className="muted">
              Removing a device revokes its credential immediately. To manage it
              again, enroll it with a new join code.
            </span>
            <Button variant="danger" onClick={() => setConfirm("remove")}>
              Remove device
            </Button>
          </div>
        </Card>
      </div>

      {confirm === "remove" && (
        <Confirm
          title={`Remove ${device.name}?`}
          confirmLabel="Remove device"
          danger
          onClose={() => setConfirm(null)}
          onConfirm={async () => {
            await api.removeDevice(id);
            navigate("/");
          }}
        >
          <p>
            The agent on this machine will be disconnected and can no longer
            sign in. Command history is kept. To uninstall the agent, run{" "}
            <code>sudo centrald-agent leave</code> on the machine.
          </p>
        </Confirm>
      )}
      {confirm && confirm !== "remove" && (
        <Confirm
          title={`${actionLabels[confirm]} on ${device.name}?`}
          confirmLabel={actionLabels[confirm]}
          danger={confirm === "reboot"}
          onClose={() => setConfirm(null)}
          onConfirm={async () => {
            try {
              await startAction(confirm);
            } catch (e) {
              setError(errorText(e));
              throw e;
            }
          }}
        >
          <p>
            {confirm === "reboot" &&
              "The machine restarts in a few seconds and reconnects when it is back."}
            {confirm === "updates_check" &&
              "Refreshes the package lists and counts pending updates."}
            {confirm === "updates_apply" &&
              "Refreshes the package lists and installs all available updates. This can take a while; you can follow the output."}
          </p>
        </Confirm>
      )}
      {renaming && (
        <RenameDialog device={device} onClose={() => setRenaming(false)} />
      )}
    </>
  );
}

function HealthPanel({ device }: { device: Device }) {
  const status = device.status;
  if (!status) return <p className="muted">No report from this device yet.</p>;
  const updates = status.updates;
  const failed = status.failedUnits;
  return (
    <ul className="list">
      <li>
        <span>Updates</span>
        {updates ? (
          updates.pending > 0 ? (
            <Badge tone="warn">
              {updates.pending} pending ({updates.manager})
            </Badge>
          ) : (
            <Badge tone="good">Up to date</Badge>
          )
        ) : (
          <span className="muted">Not checked</span>
        )}
      </li>
      <li>
        <span>Reboot</span>
        {updates?.rebootRequired ? (
          <Badge tone="warn">Required</Badge>
        ) : (
          <Badge tone="good">Not needed</Badge>
        )}
      </li>
      <li>
        <span>Services</span>
        {failed === null ? (
          <span className="muted">Not available</span>
        ) : failed.length === 0 ? (
          <Badge tone="good">All running</Badge>
        ) : (
          <span className="badges" style={{ justifyContent: "flex-end" }}>
            {failed.slice(0, 10).map((unit) => (
              <Badge key={unit} tone="bad">
                {short(unit)}
              </Badge>
            ))}
            {failed.length > 10 && <Badge>{failed.length - 10} more</Badge>}
          </span>
        )}
      </li>
      {updates && (
        <li>
          <span className="muted">Last update check</span>
          <span className="muted">{ago(updates.checkedAt)}</span>
        </li>
      )}
    </ul>
  );
}

function Chart({ points }: { points: MetricPoint[] }) {
  if (points.length < 2) {
    return (
      <p className="muted">
        History appears after the device has reported for a few minutes.
      </p>
    );
  }
  const width = 600;
  const height = 120;
  const start = points[0].at;
  const span = Math.max(1, points[points.length - 1].at - start);
  const path = (value: (p: MetricPoint) => number) =>
    points
      .map((p, i) => {
        const x = ((p.at - start) / span) * width;
        const y =
          height -
          (Math.min(100, Math.max(0, value(p))) / 100) * (height - 4) -
          2;
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  return (
    <>
      <svg
        className="chart"
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="CPU and memory over the last 24 hours"
      >
        <path
          d={path((p) => p.memory)}
          fill="none"
          stroke="var(--good)"
          strokeWidth="1.6"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d={path((p) => p.cpu)}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.6"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="chart-legend">
        <span>
          <span className="swatch" style={{ background: "var(--accent)" }} />
          CPU %
        </span>
        <span>
          <span className="swatch" style={{ background: "var(--good)" }} />
          Memory %
        </span>
        <span>since {dateTime(start)}</span>
      </div>
    </>
  );
}

function RenameDialog({
  device,
  onClose,
}: {
  device: Device;
  onClose: () => void;
}) {
  const [name, setName] = useState(device.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal
      title="Rename device"
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.renameDevice(device.id, name);
                onClose();
              } catch (e) {
                setError(errorText(e));
                setBusy(false);
              }
            }}
          >
            Save
          </Button>
        </>
      }
    >
      <input
        type="text"
        value={name}
        maxLength={64}
        onChange={(e) => setName(e.target.value)}
        aria-label="Device name"
        autoFocus
      />
      {error && <Notice tone="bad">{error}</Notice>}
    </Modal>
  );
}
