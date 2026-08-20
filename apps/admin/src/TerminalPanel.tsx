import { Channel, invoke } from "@tauri-apps/api/core";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { useEffect, useRef, useState } from "react";
import "@xterm/xterm/css/xterm.css";

export type TerminalTarget = Readonly<{
  id: string;
  name: string;
  os: string;
}>;

type ElevationChallenge = Readonly<{
  id: string;
  nonce: string;
  contextHash: string;
  expiresAt: string;
  challengeSignature: string;
}>;

type ShellOpenResult = Readonly<{
  handle: string;
}>;

type ShellEvent =
  | Readonly<{ type: "data"; sessionId: string; data: string }>
  | Readonly<{
      type: "close";
      sessionId: string;
      reason: string;
      exitCode: number;
    }>
  | Readonly<{ type: "error"; message: string }>;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function TerminalPanel({
  onTargetChange,
  profileId,
  selectedTarget,
  targets,
}: Readonly<{
  onTargetChange: (value: string) => void;
  profileId: string | null;
  selectedTarget: string;
  targets: readonly TerminalTarget[];
}>) {
  const [privilege, setPrivilege] = useState<"low" | "elevated">("low");
  const [accountUser, setAccountUser] = useState("");
  const [accountPassword, setAccountPassword] = useState("");
  const [saveCredentials, setSaveCredentials] = useState(false);
  const [opening, setOpening] = useState(false);
  const [terminalStatus, setTerminalStatus] = useState<string | null>(null);
  const [sessionOpen, setSessionOpen] = useState(false);
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const sessionRef = useRef<{ handle: string; terminal: Terminal } | null>(
    null,
  );
  const fitAddonRef = useRef<FitAddon | null>(null);

  useEffect(() => {
    return () => {
      const session = sessionRef.current;
      if (session) {
        void invoke("shell_close", { handle: session.handle }).catch(
          () => undefined,
        );
        session.terminal.dispose();
        sessionRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    function handleResize() {
      if (fitAddonRef.current && sessionRef.current) {
        fitAddonRef.current.fit();
      }
    }
    window.addEventListener("resize", handleResize);
    return () => {
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  const terminalReady = Boolean(profileId && selectedTarget);

  async function openTerminal() {
    if (!profileId || !selectedTarget) return;
    setOpening(true);
    setTerminalStatus("opening secure terminal...");
    try {
      const columns = fitAddonRef.current
        ? Math.max(
            2,
            Math.min(500, fitAddonRef.current.proposeDimensions()?.cols ?? 80),
          )
        : 80;
      const rows = fitAddonRef.current
        ? Math.max(
            2,
            Math.min(500, fitAddonRef.current.proposeDimensions()?.rows ?? 24),
          )
        : 24;
      let challengeId = "";
      let challengeSignature = "";
      if (privilege === "elevated") {
        const challenge = await invoke<ElevationChallenge>("begin_elevation", {
          profileId,
          targetId: selectedTarget,
          operation: "open_shell",
          reason: "operator requested an elevated terminal",
        });
        challengeId = challenge.id;
        challengeSignature = challenge.challengeSignature;
      }
      const channel = new Channel<ShellEvent>();
      const { handle } = await invoke<ShellOpenResult>("open_shell", {
        profileId,
        targetId: selectedTarget,
        privilege,
        columns,
        rows,
        reason: "operator requested a terminal",
        accountUser,
        accountPassword,
        saveCredentials,
        challengeId,
        challengeSignature,
        channel,
      });
      if (sessionRef.current) {
        sessionRef.current.terminal.dispose();
        sessionRef.current = null;
      }
      const terminal = new Terminal({
        cursorBlink: true,
        convertEol: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        fontSize: 13,
        scrollback: 5000,
      });
      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      fitAddonRef.current = fitAddon;
      if (terminalRef.current) {
        terminal.open(terminalRef.current);
        fitAddon.fit();
      }
      sessionRef.current = { handle, terminal };
      setSessionOpen(true);
      terminal.onData((data) => {
        void invoke("shell_input", {
          handle,
          data: bytesToBase64(new TextEncoder().encode(data)),
        }).catch((error: unknown) => {
          setTerminalStatus(String(error));
        });
      });
      terminal.onResize(({ cols, rows: newRows }) => {
        void invoke("shell_resize", {
          handle,
          columns: cols,
          rows: newRows,
        }).catch((error: unknown) => {
          setTerminalStatus(String(error));
        });
      });
      channel.onmessage = (event) => {
        if (event.type === "data") {
          const bytes = base64ToBytes(event.data);
          terminal.write(bytes);
        } else if (event.type === "close") {
          setSessionOpen(false);
          setTerminalStatus(`Session closed: ${event.reason || "ended"}`);
        } else if (event.type === "error") {
          setSessionOpen(false);
          setTerminalStatus(`Session error: ${event.message}`);
        }
      };
      setTerminalStatus("secure terminal connected");
    } catch (error) {
      setTerminalStatus(String(error));
    } finally {
      setOpening(false);
    }
  }

  function closeTerminal() {
    const session = sessionRef.current;
    if (!session) return;
    void invoke("shell_close", { handle: session.handle }).catch(
      () => undefined,
    );
    session.terminal.dispose();
    sessionRef.current = null;
    setSessionOpen(false);
    setTerminalStatus("terminal closed");
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Interactive access</p>
          <h3>Terminal</h3>
          <p>
            Secure PTY/ConPTY sessions require the terminal release gate. Until
            then this panel is not linked from navigation.
          </p>
        </div>
      </div>
      <div className="terminal-layout">
        <section className="panel terminal-connect">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Session setup</p>
              <h4>Open a managed terminal</h4>
            </div>
          </div>
          <label>
            Target
            <select
              onChange={(event) => onTargetChange(event.target.value)}
              value={selectedTarget}
            >
              <option value="">Select a device</option>
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.os})
                </option>
              ))}
            </select>
          </label>
          <label>
            Privilege
            <select
              onChange={(event) =>
                setPrivilege(
                  event.target.value === "elevated" ? "elevated" : "low",
                )
              }
              value={privilege}
            >
              <option value="low">Low (managed service account)</option>
              <option value="elevated">Elevated (root / SYSTEM)</option>
            </select>
          </label>
          <label>
            OS account
            <input
              autoComplete="off"
              onChange={(event) => setAccountUser(event.target.value)}
              placeholder={privilege === "elevated" ? "root" : "centrald"}
              value={accountUser}
            />
          </label>
          <label>
            OS account password
            <input
              autoComplete="off"
              onChange={(event) => setAccountPassword(event.target.value)}
              type="password"
              value={accountPassword}
            />
          </label>
          <label className="checkbox-row">
            <input
              checked={saveCredentials}
              onChange={(event) => setSaveCredentials(event.target.checked)}
              type="checkbox"
            />
            Save the validated credentials in this machine's OS vault
          </label>
          <div className="row-actions">
            <button
              className="button primary"
              disabled={!terminalReady || opening || sessionOpen}
              onClick={() => void openTerminal()}
              type="button"
            >
              {opening ? "Opening..." : "Open terminal"}
            </button>
            <button
              disabled={!sessionOpen}
              onClick={closeTerminal}
              type="button"
            >
              Close terminal
            </button>
          </div>
          <p className="form-help">
            Terminal execution and credential saving require the terminal
            release gate on the server, broker, and Tauri commands.
          </p>
          {terminalStatus ? (
            <p className="terminal-status">{terminalStatus}</p>
          ) : null}
        </section>
        <section className="terminal-window" aria-label="Secure terminal">
          <div className="terminal-chrome">
            <span />
            <span />
            <span />
            <strong>centrald secure terminal</strong>
          </div>
          <div className="terminal-body" ref={terminalRef}>
            <p className="terminal-muted">
              Open a session to connect the xterm view to the remote PTY.
            </p>
          </div>
        </section>
      </div>
    </>
  );
}
