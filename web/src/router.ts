// A tiny history-API router; the server returns index.html for app paths.

import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) listener();
}

window.addEventListener("popstate", notify);

export function navigate(path: string, replace = false) {
  if (path === window.location.pathname + window.location.search) return;
  if (replace) window.history.replaceState(null, "", path);
  else window.history.pushState(null, "", path);
  window.scrollTo(0, 0);
  notify();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useLocation() {
  const path = useSyncExternalStore(subscribe, () => window.location.pathname);
  const search = useSyncExternalStore(subscribe, () => window.location.search);
  return { path, query: new URLSearchParams(search) };
}

/** Matches `/devices/:id` style patterns; returns params or null. */
export function match(
  pattern: string,
  path: string,
): Record<string, string> | null {
  const a = pattern.split("/").filter(Boolean);
  const b = path.split("/").filter(Boolean);
  if (a.length !== b.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i].startsWith(":")) params[a[i].slice(1)] = decodeURIComponent(b[i]);
    else if (a[i] !== b[i]) return null;
  }
  return params;
}
