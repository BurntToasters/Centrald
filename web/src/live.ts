// Live device list and event stream over the /api/events WebSocket.

import { useEffect, useRef, useSyncExternalStore } from "react";
import { api, websocketUrl, type Device, type LiveEvent } from "./api";

type Listener = () => void;
type EventListener = (event: LiveEvent) => void;

export type ConnectionState = "connecting" | "live" | "offline";

class LiveStore {
  private devices: Device[] = [];
  private loaded = false;
  private connection: ConnectionState = "connecting";
  private listeners = new Set<Listener>();
  private eventListeners = new Set<EventListener>();
  private socket: WebSocket | null = null;
  private retry = 1000;
  private timer: number | undefined;
  private stopped = true;

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    this.open();
  }

  stop() {
    this.stopped = true;
    window.clearTimeout(this.timer);
    this.socket?.close();
    this.socket = null;
    this.devices = [];
    this.loaded = false;
    this.notify();
  }

  private open() {
    const socket = new WebSocket(websocketUrl("/events"));
    this.socket = socket;
    socket.onopen = () => {
      this.retry = 1000;
      this.setConnection("live");
      void this.refresh();
      this.broadcast({ type: "resync" });
    };
    socket.onmessage = (message) => {
      let event: LiveEvent;
      try {
        event = JSON.parse(String(message.data));
      } catch {
        return;
      }
      if (event.type === "device") this.upsert(event.device);
      else if (event.type === "device_removed") this.remove(event.id);
      else if (event.type === "resync") void this.refresh();
      this.broadcast(event);
    };
    socket.onclose = () => {
      if (this.socket !== socket) return;
      this.socket = null;
      if (this.stopped) return;
      this.setConnection("offline");
      this.timer = window.setTimeout(() => this.open(), this.retry);
      this.retry = Math.min(this.retry * 2, 15000);
    };
  }

  async refresh() {
    try {
      this.devices = await api.devices();
      this.loaded = true;
      this.notify();
    } catch {
      // The socket reconnect loop retries.
    }
  }

  private upsert(device: Device) {
    const index = this.devices.findIndex((d) => d.id === device.id);
    const next = [...this.devices];
    if (index >= 0) next[index] = device;
    else next.push(device);
    next.sort((a, b) =>
      a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
    );
    this.devices = next;
    this.notify();
  }

  private remove(id: string) {
    this.devices = this.devices.filter((d) => d.id !== id);
    this.notify();
  }

  private setConnection(state: ConnectionState) {
    this.connection = state;
    this.notify();
  }

  private notify() {
    this.snapshot = {
      devices: this.devices,
      loaded: this.loaded,
      connection: this.connection,
    };
    for (const listener of this.listeners) listener();
  }

  private broadcast(event: LiveEvent) {
    for (const listener of this.eventListeners) listener(event);
  }

  snapshot = {
    devices: [] as Device[],
    loaded: false,
    connection: "connecting" as ConnectionState,
  };

  subscribe = (listener: Listener) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  onEvent(listener: EventListener) {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }
}

export const live = new LiveStore();

export function useLive() {
  return useSyncExternalStore(live.subscribe, () => live.snapshot);
}

export function useDevice(id: string): Device | undefined {
  return useLive().devices.find((d) => d.id === id);
}

/** Calls `handler` for every live event while mounted. */
export function useLiveEvents(handler: EventListener) {
  const ref = useRef(handler);
  useEffect(() => {
    ref.current = handler;
  });
  useEffect(() => live.onEvent((event) => ref.current(event)), []);
}
