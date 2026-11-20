import { useMemo, useState } from "react";
import { api } from "../api";
import { osLabel } from "../format";
import { useLive } from "../live";
import { navigate, useLocation } from "../router";
import {
  Button,
  Card,
  Empty,
  Field,
  Notice,
  PageHeader,
  StatusDot,
  errorText,
} from "../ui";

const QUICK_LINUX = [
  "uptime",
  "df -h",
  "free -h",
  "systemctl --failed",
  "journalctl -p err -n 30 --no-pager",
  "docker ps",
];

export function RunCommand() {
  const { devices, loaded } = useLive();
  const { query } = useLocation();
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set((query.get("devices") ?? "").split(",").filter(Boolean)),
  );
  const [command, setCommand] = useState("");
  const [timeout, setTimeoutSeconds] = useState(300);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const runnable = useMemo(
    () => devices.filter((d) => d.online && d.allowCommands),
    [devices],
  );
  const chosen = [...selected].filter((id) =>
    runnable.some((d) => d.id === id),
  );

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const run = await api.startRun({
        deviceIds: chosen,
        command,
        timeoutSeconds: timeout,
      });
      navigate(`/runs/${run.id}`);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  if (loaded && devices.length === 0) {
    return (
      <>
        <PageHeader title="Run command" />
        <Card>
          <Empty
            title="No devices yet"
            action={
              <Button variant="primary" onClick={() => navigate("/add")}>
                Add a device
              </Button>
            }
          />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Run command"
        subtitle="Runs as root (Administrator on Windows) on every device you pick."
      />
      <form onSubmit={submit} className="grid grid-2">
        <Card
          title={`Devices (${chosen.length} selected)`}
          actions={
            <Button
              size="sm"
              variant="ghost"
              onClick={() =>
                setSelected(
                  chosen.length === runnable.length
                    ? new Set()
                    : new Set(runnable.map((d) => d.id)),
                )
              }
            >
              {chosen.length === runnable.length && runnable.length > 0
                ? "Select none"
                : "Select all online"}
            </Button>
          }
        >
          <div className="picker">
            {devices.map((device) => {
              const available = device.online && device.allowCommands;
              return (
                <label key={device.id} className={available ? "" : "disabled"}>
                  <input
                    type="checkbox"
                    disabled={!available}
                    checked={available && selected.has(device.id)}
                    onChange={() => toggle(device.id)}
                  />
                  <StatusDot online={device.online} />
                  <span style={{ flex: 1 }}>
                    <strong>{device.name}</strong>
                    <span className="device-sub"> · {osLabel(device)}</span>
                  </span>
                  {!device.online && <span className="muted">offline</span>}
                  {device.online && !device.allowCommands && (
                    <span className="muted">monitor-only</span>
                  )}
                </label>
              );
            })}
          </div>
        </Card>
        <Card title="Command">
          <div className="form">
            <Field
              label="Command line"
              hint="Linux runs it with /bin/sh; Windows with PowerShell."
            >
              <textarea
                rows={5}
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                placeholder="apt list --upgradable"
                spellCheck={false}
                required
                aria-label="Command line"
              />
            </Field>
            <div className="chips" aria-label="Examples">
              {QUICK_LINUX.map((example) => (
                <button
                  key={example}
                  type="button"
                  className="chip"
                  onClick={() => setCommand(example)}
                >
                  {example}
                </button>
              ))}
            </div>
            <Field
              label="Time limit"
              hint="The command is stopped if it runs longer."
            >
              <select
                value={timeout}
                onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
              >
                <option value={60}>1 minute</option>
                <option value={300}>5 minutes</option>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={21600}>6 hours</option>
              </select>
            </Field>
            {error && <Notice tone="bad">{error}</Notice>}
            <Button
              variant="primary"
              type="submit"
              busy={busy}
              disabled={chosen.length === 0 || !command.trim()}
            >
              Run on {chosen.length} device{chosen.length === 1 ? "" : "s"}
            </Button>
          </div>
        </Card>
      </form>
    </>
  );
}
