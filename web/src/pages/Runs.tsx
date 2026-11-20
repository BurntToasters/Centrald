import { useCallback, useEffect, useState } from "react";
import { api, type Run } from "../api";
import { actionLabels, ago, stateLabels, stateTones } from "../format";
import { useLiveEvents } from "../live";
import { navigate } from "../router";
import { Badge, Button, Card, Empty, PageHeader, useTick } from "../ui";

export function summarize(run: Run) {
  const counts = new Map<string, number>();
  for (const target of run.targets) {
    counts.set(target.state, (counts.get(target.state) ?? 0) + 1);
  }
  return [...counts.entries()];
}

export function runTitle(run: Run) {
  return run.kind === "action"
    ? (actionLabels[run.command] ?? run.command)
    : run.command;
}

export function Runs() {
  useTick();
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [more, setMore] = useState(true);

  const load = useCallback(async () => {
    const page = await api.runs({ limit: 50 });
    setRuns(page);
    setMore(page.length === 50);
  }, []);

  useEffect(() => {
    void load().catch(() => setRuns([]));
  }, [load]);

  useLiveEvents((event) => {
    if (event.type === "run") {
      setRuns((current) => {
        if (!current) return current;
        const index = current.findIndex((r) => r.id === event.run.id);
        if (index < 0) return [event.run, ...current];
        const next = [...current];
        next[index] = event.run;
        return next;
      });
    } else if (event.type === "resync") {
      void load().catch(() => {});
    }
  });

  return (
    <>
      <PageHeader
        title="History"
        subtitle="Commands and actions run on your devices."
        actions={
          <Button variant="primary" onClick={() => navigate("/run")}>
            Run command
          </Button>
        }
      />
      <Card>
        {runs && runs.length === 0 ? (
          <Empty title="Nothing run yet">
            Commands you run appear here with their output.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Command</th>
                  <th>Devices</th>
                  <th>Result</th>
                  <th>By</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {(runs ?? []).map((run) => (
                  <tr
                    key={run.id}
                    className="clickable"
                    onClick={() => navigate(`/runs/${run.id}`)}
                  >
                    <td
                      className="mono"
                      style={{
                        maxWidth: 380,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {runTitle(run)}
                    </td>
                    <td>
                      {run.targets.length === 1
                        ? run.targets[0].deviceName
                        : `${run.targets.length} devices`}
                    </td>
                    <td>
                      <span className="badges">
                        {summarize(run).map(([state, count]) => (
                          <Badge
                            key={state}
                            tone={stateTones[state as keyof typeof stateTones]}
                          >
                            {run.targets.length > 1 ? `${count} ` : ""}
                            {stateLabels[state as keyof typeof stateLabels]}
                          </Badge>
                        ))}
                      </span>
                    </td>
                    <td>{run.createdBy}</td>
                    <td className="nowrap muted">{ago(run.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {runs && more && runs.length > 0 && (
          <div style={{ marginTop: 16, textAlign: "center" }}>
            <Button
              onClick={async () => {
                const last = runs[runs.length - 1];
                const page = await api.runs({
                  before: last.createdAt,
                  limit: 50,
                });
                setRuns([
                  ...runs,
                  ...page.filter((r) => !runs.some((x) => x.id === r.id)),
                ]);
                setMore(page.length === 50);
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
