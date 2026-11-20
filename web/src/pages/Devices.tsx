import { useMemo, useState } from "react";
import type { Device } from "../api";
import { ago, attention, duration, osLabel, percent } from "../format";
import { useLive } from "../live";
import { navigate } from "../router";
import {
  Badge,
  Button,
  Card,
  Empty,
  Link,
  Meter,
  PageHeader,
  StatusDot,
  useTick,
} from "../ui";

function rootDiskPercent(device: Device): number | null {
  const disks = device.status?.disks ?? [];
  const root =
    disks.find((d) => d.mount === "/" || /^[A-Z]:\\?$/i.test(d.mount)) ??
    disks[0];
  return root ? percent(root.usedBytes, root.totalBytes) : null;
}

export function Devices() {
  useTick();
  const { devices, loaded } = useLive();
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return devices;
    return devices.filter((d) =>
      [d.name, d.hostname, d.os.name, ...(d.status?.addresses ?? [])]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [devices, filter]);

  const online = devices.filter((d) => d.online).length;
  const needsAttention = devices.filter(
    (d) => d.online && attention(d).length > 0,
  ).length;
  const updates = devices.reduce(
    (sum, d) => sum + (d.status?.updates?.pending ?? 0),
    0,
  );

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  if (loaded && devices.length === 0) {
    return (
      <>
        <PageHeader title="Devices" />
        <Card>
          <Empty
            title="No devices yet"
            action={
              <Button variant="primary" onClick={() => navigate("/add")}>
                Add your first device
              </Button>
            }
          >
            Install the CentralD agent on a machine to see its health here and
            run commands on it. It takes one copy-and-paste.
          </Empty>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Devices"
        subtitle={`${online} of ${devices.length} online`}
        actions={
          <>
            {selected.size > 0 && (
              <Button
                variant="primary"
                onClick={() =>
                  navigate(`/run?devices=${[...selected].join(",")}`)
                }
              >
                Run command on {selected.size} selected
              </Button>
            )}
            <Button onClick={() => navigate("/add")}>Add device</Button>
          </>
        }
      />
      <div className="grid grid-tiles" style={{ marginBottom: 16 }}>
        <Card className="tile">
          <div className="tile-value">{devices.length}</div>
          <div className="tile-label">Devices</div>
        </Card>
        <Card className="tile">
          <div className="tile-value">{online}</div>
          <div className="tile-label">Online now</div>
        </Card>
        <Card className="tile">
          <div className="tile-value">{needsAttention}</div>
          <div className="tile-label">Need attention</div>
        </Card>
        <Card className="tile">
          <div className="tile-value">{updates}</div>
          <div className="tile-label">Pending updates</div>
        </Card>
      </div>
      <Card
        title="All devices"
        actions={
          <input
            type="search"
            placeholder="Filter by name, OS, or address"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            aria-label="Filter devices"
            style={{ width: 260 }}
          />
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={
                      shown.length > 0 && shown.every((d) => selected.has(d.id))
                    }
                    onChange={(e) =>
                      setSelected(
                        e.target.checked
                          ? new Set(shown.map((d) => d.id))
                          : new Set(),
                      )
                    }
                  />
                </th>
                <th>Device</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
                <th>Uptime</th>
                <th>Health</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((device) => (
                <DeviceRow
                  key={device.id}
                  device={device}
                  selected={selected.has(device.id)}
                  onToggle={() => toggle(device.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

function DeviceRow({
  device,
  selected,
  onToggle,
}: {
  device: Device;
  selected: boolean;
  onToggle: () => void;
}) {
  const status = device.online ? device.status : null;
  const disk = status ? rootDiskPercent(device) : null;
  const notes = attention(device).filter((n) => n !== "Offline");
  return (
    <tr
      className="clickable"
      onClick={() => navigate(`/devices/${device.id}`)}
      data-testid="device-row"
    >
      <td onClick={(e) => e.stopPropagation()}>
        <input
          type="checkbox"
          aria-label={`Select ${device.name}`}
          checked={selected}
          onChange={onToggle}
        />
      </td>
      <td>
        <Link to={`/devices/${device.id}`} className="device-name">
          <StatusDot online={device.online} />
          {device.name}
        </Link>
        <div className="device-sub">
          {osLabel(device)}
          {status?.addresses[0] ? ` · ${status.addresses[0]}` : ""}
        </div>
      </td>
      <td className="mini-meter">
        {status ? (
          <Meter value={status.cpuPercent} />
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td className="mini-meter">
        {status ? (
          <Meter
            value={percent(status.memory.usedBytes, status.memory.totalBytes)}
          />
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td className="mini-meter">
        {disk !== null ? (
          <Meter value={disk} />
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td className="nowrap">
        {status ? (
          duration(status.uptimeSeconds)
        ) : (
          <span className="muted">seen {ago(device.lastSeenAt)}</span>
        )}
      </td>
      <td>
        <div className="badges">
          {!device.online && <Badge>Offline</Badge>}
          {device.online && notes.length === 0 && (
            <Badge tone="good">Healthy</Badge>
          )}
          {notes.map((note) => (
            <Badge key={note} tone="warn">
              {note}
            </Badge>
          ))}
          {!device.allowCommands && <Badge tone="info">Monitor-only</Badge>}
        </div>
      </td>
    </tr>
  );
}
