import { useEffect, useState } from "react";
import { api, type AuditEntry } from "../api";
import { dateTime } from "../format";
import { Button, Card, Empty, PageHeader } from "../ui";

const labels: Record<string, string> = {
  "setup.completed": "Set up the server",
  login: "Signed in",
  "login.failed": "Failed sign-in",
  "login.second_factor": "Asked for two-factor code",
  "account.password_changed": "Changed password",
  "account.password_reset": "Password reset on the server",
  "account.totp_enabled": "Turned on two-factor sign-in",
  "account.totp_disabled": "Turned off two-factor sign-in",
  "user.created": "Added operator",
  "user.removed": "Removed operator",
  "join_code.created": "Created join code",
  "join_code.revoked": "Revoked join code",
  "device.enrolled": "Device joined",
  "device.renamed": "Renamed device",
  "device.removed": "Removed device",
  "run.command": "Ran command",
  "run.action": "Ran action",
  "run.canceled": "Canceled run",
  "terminal.opened": "Opened terminal",
  "terminal.closed": "Closed terminal",
};

export function Activity() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [more, setMore] = useState(false);

  useEffect(() => {
    api
      .audit()
      .then((page) => {
        setEntries(page);
        setMore(page.length === 100);
      })
      .catch(() => setEntries([]));
  }, []);

  return (
    <>
      <PageHeader
        title="Activity"
        subtitle="Everything operators and devices did, newest first."
      />
      <Card>
        {entries && entries.length === 0 ? (
          <Empty title="No activity yet" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Who</th>
                  <th>What</th>
                  <th>Target</th>
                  <th>Details</th>
                  <th>From</th>
                </tr>
              </thead>
              <tbody>
                {(entries ?? []).map((entry) => (
                  <tr key={entry.id}>
                    <td className="nowrap muted">{dateTime(entry.at)}</td>
                    <td>{entry.actor}</td>
                    <td>{labels[entry.action] ?? entry.action}</td>
                    <td>{entry.target}</td>
                    <td
                      className="mono"
                      style={{ maxWidth: 320, overflowWrap: "anywhere" }}
                    >
                      {entry.detail}
                    </td>
                    <td className="mono muted">{entry.address}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {entries && more && (
          <div style={{ marginTop: 16, textAlign: "center" }}>
            <Button
              onClick={async () => {
                const page = await api.audit(entries[entries.length - 1].id);
                setEntries([...entries, ...page]);
                setMore(page.length === 100);
              }}
            >
              Load more
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}
