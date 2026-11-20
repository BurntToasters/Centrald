import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { websocketUrl } from "../api";
import { useDevice } from "../live";
import { Badge, Button, PageHeader } from "../ui";

type Phase = "connecting" | "open" | "closed";

export function Terminal({ id }: { id: string }) {
  const device = useDevice(id);
  const container = useRef<HTMLDivElement>(null);
  const [phase, setPhase] = useState<Phase>("connecting");
  const [message, setMessage] = useState("");
  const [session, setSession] = useState(0);

  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const term = new XTerm({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace',
      fontSize: 14,
      scrollback: 5000,
      theme: { background: "#0b0d12", foreground: "#e6e8eb" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(element);
    fit.fit();
    term.focus();
    setPhase("connecting");
    setMessage("");

    const url = websocketUrl(
      `/devices/${encodeURIComponent(id)}/terminal?columns=${term.cols}&rows=${term.rows}`,
    );
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";
    const encoder = new TextEncoder();
    let ended = false;

    socket.onopen = () => setPhase("open");
    socket.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
        return;
      }
      try {
        const control = JSON.parse(String(event.data)) as {
          type: string;
          message?: string;
        };
        if (control.type === "exit" || control.type === "error") {
          ended = true;
          setMessage(control.message ?? "The session ended.");
        }
      } catch {
        // Ignore unknown text frames.
      }
    };
    socket.onclose = () => {
      setPhase("closed");
      if (!ended) {
        setMessage(
          (current) =>
            current ||
            "The connection closed. The device may be offline or the session ended.",
        );
      }
      term.write("\r\n\x1b[2m[session closed]\x1b[0m\r\n");
    };

    const input = term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN)
        socket.send(encoder.encode(data));
    });
    const binaryInput = term.onBinary((data) => {
      if (socket.readyState !== WebSocket.OPEN) return;
      const bytes = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++)
        bytes[i] = data.charCodeAt(i) & 0xff;
      socket.send(bytes);
    });
    const resize = term.onResize(({ cols, rows }) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "resize", columns: cols, rows }));
      }
    });
    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // Hidden or detached; next resize fixes it.
      }
    });
    observer.observe(element);

    return () => {
      observer.disconnect();
      input.dispose();
      binaryInput.dispose();
      resize.dispose();
      socket.close();
      term.dispose();
    };
  }, [id, session]);

  return (
    <div className="terminal-page">
      <PageHeader
        back={{ to: `/devices/${id}`, label: device?.name ?? "Device" }}
        title={`Terminal${device ? ` · ${device.name}` : ""}`}
        subtitle={
          <span className="row">
            {phase === "open" && <Badge tone="good">Connected as root</Badge>}
            {phase === "connecting" && <Badge tone="info">Connecting…</Badge>}
            {phase === "closed" && <Badge>Closed</Badge>}
            {message && <span>{message}</span>}
          </span>
        }
        actions={
          phase === "closed" && (
            <Button variant="primary" onClick={() => setSession((s) => s + 1)}>
              Reconnect
            </Button>
          )
        }
      />
      <div className="terminal-frame" ref={container} data-testid="terminal" />
    </div>
  );
}
