import { useCallback, useEffect, useRef, useState } from "react";
import { api, decodeBase64, type Run, type Target } from "../api";
import {
  dateTime,
  duration,
  nowSeconds,
  stateLabels,
  stateTones,
  stripAnsi,
} from "../format";
import { useLiveEvents } from "../live";
import { navigate } from "../router";
import {
  Badge,
  Button,
  Card,
  Empty,
  Link,
  Notice,
  PageHeader,
  errorText,
} from "../ui";
import { runTitle } from "./Runs";

/** Per-device output kept as bytes so live chunks append exactly. */
type Outputs = Record<string, Uint8Array>;

function append(
  existing: Uint8Array | undefined,
  offset: number,
  chunk: Uint8Array,
) {
  const base = existing ?? new Uint8Array();
  if (offset > base.length) return base; // A gap: wait for the next full load.
  const merged = new Uint8Array(offset + chunk.length);
  merged.set(base.subarray(0, offset));
  merged.set(chunk, offset);
  return merged.length >= base.length ? merged : base;
}

export function RunDetail({ id }: { id: string }) {
  const [run, setRun] = useState<Run | null>(null);
  const [outputs, setOutputs] = useState<Outputs>({});
  const [missing, setMissing] = useState(false);
  const [error, setError] = useState("");
  const [canceling, setCanceling] = useState(false);

  const load = useCallback(async () => {
    try {
      const detail = await api.run(id);
      setRun(detail);
      const next: Outputs = {};
      for (const target of detail.targets) {
        next[target.deviceId] = decodeBase64(target.output ?? "");
      }
      setOutputs((current) => {
        // Keep whichever copy is longer: live chunks may have raced the load.
        const merged: Outputs = { ...next };
        for (const [device, bytes] of Object.entries(current)) {
          if ((merged[device]?.length ?? 0) < bytes.length)
            merged[device] = bytes;
        }
        return merged;
      });
    } catch {
      setMissing(true);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  useLiveEvents((event) => {
    if (event.type === "run_output" && event.runId === id) {
      setOutputs((current) => ({
        ...current,
        [event.deviceId]: append(
          current[event.deviceId],
          event.offset,
          decodeBase64(event.data),
        ),
      }));
    } else if (event.type === "run" && event.run.id === id) {
      const finishedNow = event.run.targets.some(
        (t) =>
          t.state !== "running" &&
          run?.targets.find((r) => r.deviceId === t.deviceId)?.state ===
            "running",
      );
      setRun((current) =>
        current
          ? {
              ...event.run,
              targets: event.run.targets.map((t) => ({
                ...t,
                output: current.targets.find((c) => c.deviceId === t.deviceId)
                  ?.output,
              })),
            }
          : event.run,
      );
      // Final output is persisted on completion; reload to be exact.
      if (finishedNow) void load();
    } else if (event.type === "resync") {
      void load();
    }
  });

  if (missing) {
    return (
      <Card>
        <Empty
          title="Run not found"
          action={
            <Button onClick={() => navigate("/runs")}>Back to history</Button>
          }
        />
      </Card>
    );
  }
  if (!run) return null;
  const running = run.targets.some((t) => t.state === "running");

  return (
    <>
      <PageHeader
        back={{ to: "/runs", label: "History" }}
        title={
          <span className={run.kind === "command" ? "mono" : ""}>
            {runTitle(run)}
          </span>
        }
        subtitle={`Started by ${run.createdBy} · ${dateTime(run.createdAt)} · time limit ${duration(run.timeoutSeconds)}`}
        actions={
          <>
            {running && (
              <Button
                variant="danger"
                busy={canceling}
                onClick={async () => {
                  setCanceling(true);
                  try {
                    await api.cancelRun(id);
                  } catch (e) {
                    setError(errorText(e));
                  }
                  setCanceling(false);
                }}
              >
                Cancel
              </Button>
            )}
            {run.kind === "command" && (
              <Button
                onClick={() =>
                  navigate(
                    `/run?devices=${run.targets.map((t) => t.deviceId).join(",")}`,
                  )
                }
              >
                Run again…
              </Button>
            )}
          </>
        }
      />
      {error && (
        <div style={{ marginBottom: 16 }}>
          <Notice tone="bad">{error}</Notice>
        </div>
      )}
      <div className="stack">
        {run.targets.map((target) => (
          <TargetCard
            key={target.deviceId}
            target={target}
            output={outputs[target.deviceId]}
          />
        ))}
      </div>
    </>
  );
}

const decoder = new TextDecoder();

function TargetCard({
  target,
  output,
}: {
  target: Target;
  output?: Uint8Array;
}) {
  const pre = useRef<HTMLPreElement>(null);
  const text = output ? stripAnsi(decoder.decode(output)) : "";
  useEffect(() => {
    const element = pre.current;
    if (element && target.state === "running")
      element.scrollTop = element.scrollHeight;
  }, [text, target.state]);
  const elapsed = (target.finishedAt ?? nowSeconds()) - target.startedAt;
  return (
    <Card
      title={
        <Link to={`/devices/${target.deviceId}`}>{target.deviceName}</Link>
      }
      actions={
        <>
          <Badge tone={stateTones[target.state]}>
            {target.state === "running" && (
              <span className="spinner" aria-hidden />
            )}
            {stateLabels[target.state]}
          </Badge>
          {target.exitCode !== null && (
            <span className="muted">exit code {target.exitCode}</span>
          )}
          <span className="muted">{duration(elapsed)}</span>
        </>
      }
    >
      {target.error && (
        <div style={{ marginBottom: 10 }}>
          <Notice
            tone={
              target.state === "failed" || target.state === "timed_out"
                ? "bad"
                : "warn"
            }
          >
            {target.error}
          </Notice>
        </div>
      )}
      {target.state !== "unreachable" && target.state !== "refused" && (
        <pre className="output" ref={pre} data-testid="run-output">
          {text}
        </pre>
      )}
      {target.truncated && (
        <p className="muted" style={{ marginBottom: 0 }}>
          Output was longer than 1 MiB; the rest was not kept.
        </p>
      )}
    </Card>
  );
}
