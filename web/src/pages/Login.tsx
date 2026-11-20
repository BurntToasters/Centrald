import { useState } from "react";
import { ApiError, api } from "../api";
import { Button, Card, Field, Notice, errorText } from "../ui";

export function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(username, password, needsCode ? code : undefined);
      onDone();
    } catch (e) {
      if (e instanceof ApiError && e.body.totpRequired) {
        if (needsCode) setError(e.message);
        setNeedsCode(true);
      } else {
        setError(errorText(e));
      }
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
        <h1>Sign in</h1>
        <form className="form" onSubmit={submit} style={{ marginTop: 20 }}>
          {!needsCode ? (
            <>
              <Field label="Username">
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  required
                  autoFocus
                />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </Field>
            </>
          ) : (
            <Field
              label="Authentication code"
              hint="Open your authenticator app and enter the 6-digit code for CentralD."
            >
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9 ]*"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                maxLength={7}
                required
                autoFocus
              />
            </Field>
          )}
          {error && <Notice tone="bad">{error}</Notice>}
          <Button variant="primary" type="submit" busy={busy}>
            {needsCode ? "Verify" : "Sign in"}
          </Button>
          {needsCode && (
            <Button
              variant="ghost"
              onClick={() => {
                setNeedsCode(false);
                setCode("");
                setError("");
              }}
            >
              Back
            </Button>
          )}
        </form>
        <p className="muted" style={{ fontSize: "0.85rem", marginTop: 18 }}>
          Forgot your password? On the server run{" "}
          <code>sudo centrald-server reset-password &lt;username&gt;</code>.
        </p>
      </Card>
    </div>
  );
}
