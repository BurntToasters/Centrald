// Writes e2e-report/{REPORT.md,report.json,SHA256SUMS} after every run.
import type {
  FullResult,
  Reporter,
  TestCase,
  TestResult,
  TestStep,
} from "@playwright/test/reporter";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { AGENT_BIN, REPORT_DIR, ROOT, SERVER_BIN } from "./harness";

type Row = {
  project: string;
  title: string;
  status: string;
  durationMs: number;
  steps: string[];
  error?: string;
};

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function git(...args: string[]): string {
  try {
    return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

function walk(dir: string, base = dir): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (name === "test-output" || name === "SHA256SUMS") return [];
    return statSync(full).isDirectory()
      ? walk(full, base)
      : [path.relative(base, full)];
  });
}

function stepTitles(steps: TestStep[]): string[] {
  return steps
    .filter((step) => step.category === "test.step")
    .flatMap((step) => [
      step.error ? `${step.title} (failed)` : step.title,
      ...stepTitles(step.steps).map((child) => `  ${child}`),
    ]);
}

export default class E2eReporter implements Reporter {
  private rows: Row[] = [];
  private started = new Date();

  onTestEnd(test: TestCase, result: TestResult) {
    this.rows.push({
      project: test.parent.project()?.name ?? "",
      title: test.title,
      status: result.status,
      durationMs: result.duration,
      steps: stepTitles(result.steps),
      error: result.error?.message?.split("\n")[0],
    });
  }

  onEnd(result: FullResult) {
    mkdirSync(REPORT_DIR, { recursive: true });
    const binaries = Object.fromEntries(
      [SERVER_BIN, AGENT_BIN]
        .filter((file) => existsSync(file))
        .map((file) => [path.basename(file), sha256(file)]),
    );
    const passed = this.rows.filter((r) => r.status === "passed").length;
    const summary = {
      result: result.status,
      startedAt: this.started.toISOString(),
      commit: git("rev-parse", "HEAD"),
      dirtyTree: git("status", "--porcelain") !== "",
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
      node: process.version,
      binaries,
      passed,
      total: this.rows.length,
      tests: this.rows,
    };
    writeFileSync(
      path.join(REPORT_DIR, "report.json"),
      `${JSON.stringify(summary, null, 2)}\n`,
    );

    const lines = [
      "# CentralD end-to-end report",
      "",
      `Result: **${result.status}** (${passed}/${this.rows.length} tests passed)`,
      "",
      `- Started: ${summary.startedAt}`,
      `- Commit: \`${summary.commit}\`${summary.dirtyTree ? " (uncommitted changes)" : ""}`,
      `- Platform: ${summary.platform}, Node ${summary.node}`,
      ...Object.entries(binaries).map(
        ([name, hash]) => `- \`${name}\` SHA-256: \`${hash}\``,
      ),
      "",
      "Reproduce with `npm run e2e` from a clean checkout of the commit above.",
      "Every file in this directory is listed with its hash in `SHA256SUMS`.",
      "",
      "| Suite | Test | Result | Time |",
      "| --- | --- | --- | --- |",
      ...this.rows.map(
        (r) =>
          `| ${r.project} | ${r.title} | ${r.status} | ${(r.durationMs / 1000).toFixed(1)} s |`,
      ),
      "",
    ];
    for (const row of this.rows) {
      lines.push(`## ${row.project}: ${row.title}`, "");
      for (const step of row.steps)
        lines.push(`${step.startsWith("  ") ? "  " : ""}- ${step.trim()}`);
      if (row.error) lines.push("", `Error: \`${row.error}\``);
      lines.push("");
    }
    const shots = walk(path.join(REPORT_DIR, "screenshots"));
    if (shots.length) {
      lines.push("## Screenshots", "");
      for (const shot of shots.sort()) {
        lines.push(`![${shot}](screenshots/${shot})`, "");
      }
    }
    writeFileSync(path.join(REPORT_DIR, "REPORT.md"), lines.join("\n"));

    const sums = walk(REPORT_DIR)
      .sort()
      .map((file) => `${sha256(path.join(REPORT_DIR, file))}  ${file}`);
    writeFileSync(path.join(REPORT_DIR, "SHA256SUMS"), `${sums.join("\n")}\n`);
  }

  printsToStdio() {
    return false;
  }
}
