import { useCallback, useEffect, useState } from "react";
import {
  api,
  type Operator,
  type ServerInfo,
  type TotpSetup,
  type User,
} from "../api";
import { bytes, dateTime } from "../format";
import {
  Badge,
  Button,
  Card,
  Confirm,
  CopyBlock,
  Field,
  Modal,
  Notice,
  PageHeader,
  errorText,
} from "../ui";

export function Settings({
  user,
  onAccountChange,
}: {
  user: User;
  onAccountChange: () => void;
}) {
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid grid-2">
        <PasswordCard />
        <TwoFactorCard user={user} onChange={onAccountChange} />
        <OperatorsCard user={user} />
        <ServerCard />
      </div>
    </>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{
    tone: "good" | "bad";
    text: string;
  } | null>(null);
  return (
    <Card title="Password">
      <form
        className="form"
        onSubmit={async (event) => {
          event.preventDefault();
          setBusy(true);
          setMessage(null);
          try {
            await api.changePassword(current, next);
            setCurrent("");
            setNext("");
            setMessage({
              tone: "good",
              text: "Password changed. Other sessions were signed out.",
            });
          } catch (e) {
            setMessage({ tone: "bad", text: errorText(e) });
          }
          setBusy(false);
        }}
      >
        <Field label="Current password">
          <input
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>
        <Field label="New password" hint="At least 10 characters.">
          <input
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
            minLength={10}
            required
          />
        </Field>
        {message && <Notice tone={message.tone}>{message.text}</Notice>}
        <div>
          <Button type="submit" variant="primary" busy={busy}>
            Change password
          </Button>
        </div>
      </form>
    </Card>
  );
}

function TwoFactorCard({
  user,
  onChange,
}: {
  user: User;
  onChange: () => void;
}) {
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [disabling, setDisabling] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  return (
    <Card
      title="Two-factor sign-in"
      actions={
        user.totpEnabled ? <Badge tone="good">On</Badge> : <Badge>Off</Badge>
      }
    >
      {user.totpEnabled ? (
        <div className="stack" style={{ gap: 12 }}>
          <p style={{ margin: 0 }}>
            Signing in asks for a code from your authenticator app.
          </p>
          <div>
            <Button onClick={() => setDisabling(true)}>Turn off</Button>
          </div>
        </div>
      ) : setup ? (
        <form
          className="form"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError("");
            try {
              await api.totpEnable(code, password);
              setSetup(null);
              setCode("");
              setPassword("");
              onChange();
            } catch (e) {
              setError(errorText(e));
            }
            setBusy(false);
          }}
        >
          <p style={{ margin: 0 }}>
            Scan this with an authenticator app (such as Aegis, 2FAS, Google
            Authenticator, or 1Password), then enter the code it shows.
          </p>
          <div className="qr">
            <img
              src={`data:image/svg+xml;utf8,${encodeURIComponent(setup.qrSvg)}`}
              alt="QR code for your authenticator app"
              width={200}
              height={200}
            />
          </div>
          <Field label="Or enter this key by hand">
            <CopyBlock label="Two-factor secret" text={setup.secret} />
          </Field>
          <Field label="Code from the app">
            <input
              type="text"
              inputMode="numeric"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              maxLength={7}
              required
            />
          </Field>
          <Field label="Your current password">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </Field>
          {error && <Notice tone="bad">{error}</Notice>}
          <div className="row">
            <Button type="submit" variant="primary" busy={busy}>
              Turn on
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                setSetup(null);
                setPassword("");
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <div className="stack" style={{ gap: 12 }}>
          <p style={{ margin: 0 }}>
            Protect your account with a code from your phone in addition to your
            password. Recommended, since this account can run commands as root
            on your machines.
          </p>
          {error && <Notice tone="bad">{error}</Notice>}
          <div>
            <Button
              variant="primary"
              busy={busy}
              onClick={async () => {
                setBusy(true);
                setError("");
                try {
                  setSetup(await api.totpSetup());
                } catch (e) {
                  setError(errorText(e));
                }
                setBusy(false);
              }}
            >
              Set up two-factor sign-in
            </Button>
          </div>
        </div>
      )}
      {disabling && (
        <Confirm
          title="Turn off two-factor sign-in?"
          confirmLabel="Turn off"
          danger
          onClose={() => {
            setDisabling(false);
            setPassword("");
          }}
          onConfirm={async () => {
            await api.totpDisable(password);
            onChange();
          }}
        >
          <Field label="Confirm with your password">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              autoFocus
            />
          </Field>
        </Confirm>
      )}
    </Card>
  );
}

function OperatorsCard({ user }: { user: User }) {
  const [operators, setOperators] = useState<Operator[]>([]);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Operator | null>(null);
  const load = useCallback(() => {
    api
      .users()
      .then(setOperators)
      .catch(() => {});
  }, []);
  useEffect(load, [load]);

  return (
    <Card
      title="Operators"
      actions={
        <Button size="sm" onClick={() => setAdding(true)}>
          Add operator
        </Button>
      }
    >
      <p className="muted" style={{ marginTop: 0 }}>
        Every operator has full access to every device.
      </p>
      <ul className="list">
        {operators.map((operator) => (
          <li key={operator.id}>
            <span>
              <strong>{operator.username}</strong>
              {operator.id === user.id && <span className="muted"> (you)</span>}
              <span className="device-sub">
                {" "}
                · since {dateTime(operator.createdAt)}
              </span>
            </span>
            <span className="row">
              {operator.totpEnabled && <Badge tone="good">2FA</Badge>}
              {operator.id !== user.id && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setRemoving(operator)}
                >
                  Remove
                </Button>
              )}
            </span>
          </li>
        ))}
      </ul>
      {adding && (
        <AddOperator onClose={() => setAdding(false)} onAdded={load} />
      )}
      {removing && (
        <Confirm
          title={`Remove ${removing.username}?`}
          confirmLabel="Remove"
          danger
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await api.deleteUser(removing.id);
            load();
          }}
        >
          <p>They are signed out everywhere and can no longer sign in.</p>
        </Confirm>
      )}
    </Card>
  );
}

function AddOperator({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal
      title="Add operator"
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            busy={busy}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                await api.createUser(username, password);
                onAdded();
                onClose();
              } catch (e) {
                setError(errorText(e));
                setBusy(false);
              }
            }}
          >
            Add
          </Button>
        </>
      }
    >
      <Field label="Username">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="off"
          autoFocus
        />
      </Field>
      <Field
        label="Initial password"
        hint="At least 10 characters. They can change it in Settings."
      >
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
      </Field>
      {error && <Notice tone="bad">{error}</Notice>}
    </Modal>
  );
}

function ServerCard() {
  const [info, setInfo] = useState<ServerInfo | null>(null);
  useEffect(() => {
    api
      .server()
      .then(setInfo)
      .catch(() => {});
  }, []);
  if (!info) return <Card title="Server">Loading…</Card>;
  return (
    <Card title="Server">
      <dl className="facts">
        <dt>Version</dt>
        <dd>{info.version}</dd>
        <dt>Port</dt>
        <dd>{info.port}</dd>
        <dt>Certificate</dt>
        <dd>
          {info.customCertificate
            ? "Your own certificate (browsers)"
            : "Built-in certificate authority"}
        </dd>
        <dt>Names</dt>
        <dd className="mono">{info.certificateNames.join(", ")}</dd>
        <dt>CA fingerprint</dt>
        <dd className="mono" style={{ fontSize: "0.78rem" }}>
          {info.caFingerprint}
        </dd>
      </dl>
      <p className="muted" style={{ fontSize: "0.88rem" }}>
        To stop the browser warning, install the CentralD certificate authority
        on your computer and mark it trusted for websites. Agents never need
        this; they check the fingerprint above.
      </p>
      <a
        className="btn btn-secondary btn-sm"
        href="/api/server/ca.crt"
        download
      >
        Download CA certificate
      </a>
      <h3 style={{ marginTop: 20, marginBottom: 8 }}>
        Agents offered to new devices
      </h3>
      {info.agentBuilds.length === 0 ? (
        <Notice tone="warn">
          No agent binaries found on the server, so install commands cannot
          download one. Install the server package, or place builds in the agent
          directory (see the operations guide).
        </Notice>
      ) : (
        <ul className="list">
          {info.agentBuilds.map((build) => (
            <li key={`${build.os}-${build.arch}`}>
              <span>
                {build.os === "linux" ? "Linux" : "Windows"} {build.arch}
              </span>
              <span className="muted">{bytes(build.size)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
