import {
  Suspense,
  lazy,
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, setSignedOutHandler, type AppState, type User } from "./api";
import { live, useLive } from "./live";
import { match, navigate, useLocation } from "./router";
import { Link, Notice } from "./ui";
import { Setup } from "./pages/Setup";
import { Login } from "./pages/Login";
import { Devices } from "./pages/Devices";
import { DeviceDetail } from "./pages/DeviceDetail";
import { RunCommand } from "./pages/RunCommand";
import { Runs } from "./pages/Runs";
import { RunDetail } from "./pages/RunDetail";
import { AddDevice } from "./pages/AddDevice";
import { Activity } from "./pages/Activity";
import { Settings } from "./pages/Settings";

// xterm is large; load it only when a terminal opens.
const Terminal = lazy(() =>
  import("./pages/Terminal").then((m) => ({ default: m.Terminal })),
);

export function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    try {
      setState(await api.state());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void reload();
    setSignedOutHandler(() => {
      live.stop();
      setState((current) => (current ? { ...current, user: null } : current));
    });
  }, [reload]);

  if (!state) {
    return (
      <div className="auth">
        {error ? (
          <Notice tone="bad">Cannot reach the CentralD server: {error}</Notice>
        ) : (
          <span className="muted">Loading…</span>
        )}
      </div>
    );
  }
  if (state.setupRequired) return <Setup onDone={reload} />;
  if (!state.user) return <Login onDone={reload} />;
  return (
    <Shell
      user={state.user}
      version={state.version}
      onSignOut={async () => {
        await api.logout().catch(() => {});
        live.stop();
        navigate("/", true);
        await reload();
      }}
      onAccountChange={reload}
    />
  );
}

const icons: Record<string, ReactNode> = {
  devices: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </svg>
  ),
  run: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="m5 7 5 5-5 5M12 17h7" />
    </svg>
  ),
  history: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 3v5h5M12 7v5l3 2" />
    </svg>
  ),
  add: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v8M8 12h8" />
    </svg>
  ),
  activity: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M4 6h16M4 12h16M4 18h10" />
    </svg>
  ),
  settings: (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" />
    </svg>
  ),
};

const nav = [
  { to: "/", label: "Devices", icon: "devices", match: ["/", "/devices"] },
  { to: "/run", label: "Run command", icon: "run", match: ["/run"] },
  { to: "/runs", label: "History", icon: "history", match: ["/runs"] },
  { to: "/add", label: "Add device", icon: "add", match: ["/add"] },
  {
    to: "/activity",
    label: "Activity",
    icon: "activity",
    match: ["/activity"],
  },
  {
    to: "/settings",
    label: "Settings",
    icon: "settings",
    match: ["/settings"],
  },
];

function isActive(path: string, prefixes: string[]) {
  return prefixes.some((prefix) =>
    prefix === "/"
      ? path === "/"
      : path === prefix || path.startsWith(`${prefix}/`),
  );
}

function Shell({
  user,
  version,
  onSignOut,
  onAccountChange,
}: {
  user: User;
  version: string;
  onSignOut: () => void;
  onAccountChange: () => void;
}) {
  const { path } = useLocation();
  const { connection } = useLive();

  useEffect(() => {
    live.start();
  }, []);

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" />
          CentralD
        </Link>
        {nav.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            className={`nav-link ${isActive(path, item.match) ? "active" : ""}`}
          >
            {icons[item.icon]}
            <span>{item.label}</span>
          </Link>
        ))}
        <div className="sidebar-footer">
          <span className="connection muted">
            <span
              className={`dot ${connection === "live" ? "dot-online" : "dot-offline"}`}
            />
            {connection === "live"
              ? "Live"
              : connection === "connecting"
                ? "Connecting…"
                : "Reconnecting…"}
          </span>
          <span className="muted">
            Signed in as <strong>{user.username}</strong>
          </span>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onSignOut}
          >
            Sign out
          </button>
          <span className="muted">v{version}</span>
        </div>
      </nav>
      <main className="main">
        <Page path={path} user={user} onAccountChange={onAccountChange} />
      </main>
    </div>
  );
}

function Page({
  path,
  user,
  onAccountChange,
}: {
  path: string;
  user: User;
  onAccountChange: () => void;
}) {
  let params: Record<string, string> | null;
  if (path === "/" || path === "/devices") return <Devices />;
  if ((params = match("/devices/:id/terminal", path)))
    return (
      <Suspense fallback={<span className="muted">Loading terminal…</span>}>
        <Terminal key={params.id} id={params.id} />
      </Suspense>
    );
  if ((params = match("/devices/:id", path)))
    return <DeviceDetail key={params.id} id={params.id} />;
  if (path === "/run") return <RunCommand />;
  if (path === "/runs") return <Runs />;
  if ((params = match("/runs/:id", path)))
    return <RunDetail key={params.id} id={params.id} />;
  if (path === "/add") return <AddDevice />;
  if (path === "/activity") return <Activity />;
  if (path === "/settings")
    return <Settings user={user} onAccountChange={onAccountChange} />;
  return (
    <Notice tone="warn">
      This page does not exist. <Link to="/">Go to devices</Link>.
    </Notice>
  );
}
