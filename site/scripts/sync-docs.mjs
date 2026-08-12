import { readFile, mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const siteRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const repoRoot = path.resolve(siteRoot, "..");
const repoDocs = path.join(repoRoot, "docs");
const outputDir = path.join(siteRoot, "src", "content", "docs");

const documents = [
  {
    source: "QUICKSTART.md",
    sourceDir: repoDocs,
    slug: "quickstart",
    title: "Get started",
    group: "Getting started",
    order: 10,
  },
  {
    source: "ARCHITECTURE.md",
    sourceDir: repoDocs,
    slug: "architecture",
    title: "Architecture",
    group: "Architecture",
    order: 20,
  },
  {
    source: "OPERATIONS.md",
    sourceDir: repoDocs,
    slug: "operations",
    title: "Operations",
    group: "Operations",
    order: 30,
  },
  {
    source: "THREAT_MODEL.md",
    sourceDir: repoDocs,
    slug: "threat-model",
    title: "Threat model",
    group: "Security",
    order: 40,
  },
  {
    source: "SECURITY.md",
    sourceDir: repoRoot,
    slug: "security",
    title: "Security policy",
    group: "Security",
    order: 45,
  },
  {
    source: "RELEASES.md",
    sourceDir: repoDocs,
    slug: "releases",
    title: "Releases",
    group: "Project",
    order: 50,
  },
  {
    source: "IMPLEMENTATION_STATUS.md",
    sourceDir: repoDocs,
    slug: "implementation-status",
    title: "Implementation status",
    group: "Project",
    order: 60,
  },
];

function frontmatter(value) {
  const escaped = value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  return `"${escaped}"`;
}

function description(body) {
  const paragraph = body
    .split("\n")
    .map((line) => line.trim())
    .find(
      (line) =>
        line.length > 0 && !line.startsWith("#") && !line.startsWith("```"),
    );
  if (!paragraph) return "";
  const single = paragraph.replaceAll(/\s+/g, " ").trim();
  return single.length > 200 ? `${single.slice(0, 197)}...` : single;
}

const missing = [];
for (const document of documents) {
  try {
    await readFile(path.join(document.sourceDir, document.source), "utf8");
  } catch {
    missing.push(`${document.sourceDir}/${document.source}`);
  }
}
if (missing.length > 0) {
  throw new Error(`site:docs: source documents missing: ${missing.join(", ")}`);
}

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

for (const document of documents) {
  const raw = await readFile(
    path.join(document.sourceDir, document.source),
    "utf8",
  );
  const heading = raw.match(/^# (.+)$/m)?.[1]?.trim();
  const body = raw.replace(/^# .+\n?/, "");
  const title = heading || document.title;
  const content = [
    "---",
    `title: ${frontmatter(title)}`,
    `description: ${frontmatter(description(body))}`,
    `order: ${document.order}`,
    `group: ${frontmatter(document.group)}`,
    "---",
    "",
    body.trimEnd(),
    "",
  ].join("\n");
  await writeFile(path.join(outputDir, `${document.slug}.md`), content, "utf8");
}

console.log(
  `site:docs: synced ${documents.length} documents into src/content/docs`,
);
