import { useState } from "react";
import { api } from "../api";
import { Button, Card, Field, Notice, errorText } from "../ui";

export function Setup({ onDone }: { onDone: () => void }) {
  const [setupCode, setSetupCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.setup(setupCode, username, password);
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <Card className="auth-card">
        <div className="brand">
          <img src="/favicon.svg" alt="" />
          CentralD
        </div>
        <h1>Welcome</h1>
        <p className="subtitle">
          Create the account you will use to manage your machines.
        </p>
        <form className="form" onSubmit={submit} style={{ marginTop: 20 }}>
          <Field
            label="Setup code"
            hint={
              <>
                On the server, run <code>sudo centrald-server status</code> to
                see it. It proves you control this server.
              </>
            }
          >
            <input
              type="text"
              value={setupCode}
              onChange={(e) => setSetupCode(e.target.value)}
              placeholder="XXXX-XXXX-XXXX"
              autoComplete="off"
              spellCheck={false}
              required
              autoFocus
            />
          </Field>
          <Field label="Username">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </Field>
          <Field label="Password" hint="At least 10 characters.">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              minLength={10}
              required
            />
          </Field>
          <Field label="Confirm password">
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
            />
          </Field>
          {error && <Notice tone="bad">{error}</Notice>}
          <Button variant="primary" type="submit" busy={busy}>
            Create account
          </Button>
        </form>
      </Card>
    </div>
  );
}
