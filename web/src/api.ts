// Typed client for the CentralD server API. Field names mirror the server's
// camelCase JSON exactly.

export interface OsInfo {
  family: string;
  id: string;
  name: string;
  version: string;
  kernel: string;
  arch: string;
}

export interface Usage {
  totalBytes: number;
  usedBytes: number;
}

export interface Disk {
  mount: string;
  filesystem: string;
  totalBytes: number;
  usedBytes: number;
}

export interface Updates {
  manager: string;
  pending: number;
  rebootRequired: boolean;
  checkedAt: number;
}

export interface Status {
  uptimeSeconds: number;
  cpuPercent: number;
  cpuCount: number;
  load: [number, number, number] | null;
  memory: Usage;
  swap: Usage;
  disks: Disk[];
  addresses: string[];
  updates: Updates | null;
  failedUnits: string[] | null;
}

export interface Device {
  id: string;
  name: string;
  hostname: string;
  os: OsInfo;
  agentVersion: string;
  allowCommands: boolean;
  packageManaged: boolean;
  enrolledAt: number;
  lastSeenAt: number | null;
  lastAddress: string | null;
  online: boolean;
  status: Status | null;
  statusAt: number | null;
}

export type TargetState =
  | "running"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "canceled"
  | "refused"
  | "unreachable"
  | "lost";

export interface Target {
  deviceId: string;
  deviceName: string;
  state: TargetState;
  exitCode: number | null;
  error: string | null;
  startedAt: number;
  finishedAt: number | null;
  /** Base64; only present on run detail. */
  output?: string;
  outputBytes: number;
  truncated: boolean;
}

export interface Run {
  id: string;
  kind: "command" | "action";
  command: string;
  createdBy: string;
  createdAt: number;
  timeoutSeconds: number;
  targets: Target[];
}

export type ActionName = "reboot" | "updates_check" | "updates_apply";

export interface JoinToken {
  id: string;
  name: string;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
  deviceId: string | null;
}

export interface CreatedJoinToken {
  id: string;
  code: string;
  expiresAt: number;
  servers: string[];
  linuxCommand: string;
  windowsCommand: string;
}

export interface AuditEntry {
  id: number;
  at: number;
  actor: string;
  action: string;
  target: string;
  detail: string;
  address: string;
}

export interface User {
  id: string;
  username: string;
  totpEnabled: boolean;
}

export interface Operator extends User {
  createdAt: number;
}

export interface AppState {
  setupRequired: boolean;
  user: User | null;
  version: string;
}

export interface AgentBuild {
  os: string;
  arch: string;
  sha256: string;
  size: number;
}

export interface ServerInfo {
  version: string;
  caFingerprint: string;
  certificateNames: string[];
  customCertificate: boolean;
  port: number;
  agentBuilds: AgentBuild[];
}

export interface MetricPoint {
  at: number;
  cpu: number;
  memory: number;
  load: number | null;
}

export interface TotpSetup {
  secret: string;
  uri: string;
  qrSvg: string;
}

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;
  constructor(status: number, message: string, body: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/** Called when any request finds the session gone. */
let onSignedOut: () => void = () => {};
export function setSignedOutHandler(handler: () => void) {
  onSignedOut = handler;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data: Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!response.ok) {
    const message =
      typeof data.error === "string"
        ? data.error
        : `Request failed (${response.status})`;
    if (response.status === 401 && path !== "/login" && path !== "/setup") {
      onSignedOut();
    }
    throw new ApiError(response.status, message, data);
  }
  return data as T;
}

const get = <T>(path: string) => request<T>("GET", path);
const post = <T>(path: string, body: unknown = {}) =>
  request<T>("POST", path, body);

export const api = {
  state: () => get<AppState>("/state"),
  setup: (setupCode: string, username: string, password: string) =>
    post("/setup", { setupCode, username, password }),
  login: (username: string, password: string, totpCode?: string) =>
    post("/login", { username, password, totpCode }),
  logout: () => post("/logout"),
  changePassword: (currentPassword: string, newPassword: string) =>
    post("/account/password", { currentPassword, newPassword }),
  totpSetup: () => post<TotpSetup>("/account/totp/setup"),
  totpEnable: (code: string, password: string) =>
    post("/account/totp/enable", { code, password }),
  totpDisable: (password: string) =>
    post("/account/totp/disable", { password }),

  users: () => get<Operator[]>("/users"),
  createUser: (username: string, password: string) =>
    post<{ id: string }>("/users", { username, password }),
  deleteUser: (id: string) => request("DELETE", `/users/${id}`),

  devices: () => get<Device[]>("/devices"),
  device: (id: string) => get<Device>(`/devices/${id}`),
  renameDevice: (id: string, name: string) =>
    request("PATCH", `/devices/${id}`, { name }),
  removeDevice: (id: string) => request("DELETE", `/devices/${id}`),
  metrics: (id: string, hours = 24) =>
    get<MetricPoint[]>(`/devices/${id}/metrics?hours=${hours}`),

  joinTokens: () => get<JoinToken[]>("/join-tokens"),
  createJoinToken: (body: {
    name: string;
    serverAddress: string;
    expiresInHours: number;
    monitorOnly: boolean;
  }) => post<CreatedJoinToken>("/join-tokens", body),
  revokeJoinToken: (id: string) => request("DELETE", `/join-tokens/${id}`),

  runs: (
    params: { deviceId?: string; before?: number; limit?: number } = {},
  ) => {
    const query = new URLSearchParams();
    if (params.deviceId) query.set("deviceId", params.deviceId);
    if (params.before) query.set("before", String(params.before));
    if (params.limit) query.set("limit", String(params.limit));
    const suffix = query.size ? `?${query}` : "";
    return get<Run[]>(`/runs${suffix}`);
  },
  run: (id: string) => get<Run>(`/runs/${id}`),
  startRun: (body: {
    deviceIds: string[];
    command?: string;
    action?: ActionName;
    timeoutSeconds?: number;
  }) => post<Run>("/runs", body),
  cancelRun: (id: string) => post<{ canceled: number }>(`/runs/${id}/cancel`),

  audit: (before?: number) =>
    get<AuditEntry[]>(`/audit${before ? `?before=${before}` : ""}`),
  server: () => get<ServerInfo>("/server"),
};

export type LiveEvent =
  | { type: "device"; device: Device }
  | { type: "device_removed"; id: string }
  | { type: "run"; run: Run }
  | {
      type: "run_output";
      runId: string;
      deviceId: string;
      offset: number;
      data: string;
    }
  | { type: "join_tokens" }
  | { type: "resync" };

export function websocketUrl(path: string): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}/api${path}`;
}

/** Decodes base64 into bytes. */
export function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
