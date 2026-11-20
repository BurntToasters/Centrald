import type { Device, TargetState } from "./api";

export function bytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const exponent = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const scaled = value / 1024 ** exponent;
  return `${scaled >= 100 || exponent === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[exponent]}`;
}

export function percent(used: number, total: number): number {
  return total > 0 ? Math.min(100, Math.max(0, (used / total) * 100)) : 0;
}

export function duration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${s}s`;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function ago(unix: number | null | undefined): string {
  if (!unix) return "never";
  const delta = nowSeconds() - unix;
  if (delta < 10) return "just now";
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)} min ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)} h ago`;
  return `${Math.floor(delta / 86400)} d ago`;
}

export function dateTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function osLabel(device: Device): string {
  return device.os.name || device.os.family || "Unknown OS";
}

export const stateLabels: Record<TargetState, string> = {
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  timed_out: "Timed out",
  canceled: "Canceled",
  refused: "Refused",
  unreachable: "Offline",
  lost: "Interrupted",
};

export type Tone = "good" | "bad" | "warn" | "info" | "muted";

export const stateTones: Record<TargetState, Tone> = {
  running: "info",
  succeeded: "good",
  failed: "bad",
  timed_out: "bad",
  canceled: "muted",
  refused: "warn",
  unreachable: "muted",
  lost: "warn",
};

export const actionLabels: Record<string, string> = {
  reboot: "Reboot",
  updates_check: "Check for updates",
  updates_apply: "Install updates",
};

/** Things about a device worth an operator's attention. */
export function attention(device: Device): string[] {
  const notes: string[] = [];
  const status = device.status;
  if (!device.online) notes.push("Offline");
  if (!status) return notes;
  if (status.updates && status.updates.pending > 0)
    notes.push(
      `${status.updates.pending} update${status.updates.pending === 1 ? "" : "s"}`,
    );
  if (status.updates?.rebootRequired) notes.push("Reboot required");
  if (status.failedUnits && status.failedUnits.length > 0)
    notes.push(
      `${status.failedUnits.length} failed service${status.failedUnits.length === 1 ? "" : "s"}`,
    );
  for (const disk of status.disks) {
    if (percent(disk.usedBytes, disk.totalBytes) >= 90)
      notes.push(`${disk.mount} almost full`);
  }
  return notes;
}

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(\x07|\x1b\\)/g;

/** Drops ANSI escape sequences for plain-text output views. */
export function stripAnsi(text: string): string {
  return text.replace(ANSI, "");
}
