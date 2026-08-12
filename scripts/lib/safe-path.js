import fs from "node:fs";
import path from "node:path";

export const GENERATED_MARKER = ".centrald-generated";
export const ALLOWED_GENERATED_ROOTS = Object.freeze([
  "coverage",
  "dist",
  "release",
  "target",
]);

function canonicalExisting(value) {
  return fs.realpathSync.native(value);
}

function assertRealDirectoryComponent(component, label) {
  const stats = fs.lstatSync(component);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error(`${label} contains an unsafe path component: ${component}`);
  }
}

function validateExistingComponents(canonicalRoot, resolved, relativeTarget) {
  const relative = path.relative(canonicalRoot, resolved);
  let current = canonicalRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) break;
    assertRealDirectoryComponent(current, `Generated target ${relativeTarget}`);
    const canonicalComponent = canonicalExisting(current);
    const componentRelative = path.relative(canonicalRoot, canonicalComponent);
    if (
      componentRelative === ".." ||
      componentRelative.startsWith(`..${path.sep}`)
    ) {
      throw new Error(
        `Generated target resolves outside repository: ${relativeTarget}`,
      );
    }
  }
}

export function resolveGeneratedTarget(root, relativeTarget) {
  const canonicalRoot = canonicalExisting(root);
  if (
    typeof relativeTarget !== "string" ||
    relativeTarget.length === 0 ||
    path.isAbsolute(relativeTarget) ||
    relativeTarget.includes("\0")
  ) {
    throw new Error(
      "Generated target must be a non-empty repository-relative path.",
    );
  }

  const normalized = path.normalize(relativeTarget);
  const firstSegment = normalized.split(path.sep)[0];
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    !ALLOWED_GENERATED_ROOTS.includes(firstSegment)
  ) {
    throw new Error(`Generated target is not allowlisted: ${relativeTarget}`);
  }

  const resolved = path.resolve(canonicalRoot, normalized);
  const relative = path.relative(canonicalRoot, resolved);
  if (
    relative.length === 0 ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.parse(resolved).root === resolved
  ) {
    throw new Error(`Generated target escapes repository: ${relativeTarget}`);
  }

  // Check every existing ancestor before mkdir. Checking only the final path
  // permits an attacker-controlled symlink/junction such as dist -> /tmp/out.
  validateExistingComponents(canonicalRoot, resolved, relativeTarget);
  return resolved;
}

function createDirectoryComponents(canonicalRoot, target, relativeTarget) {
  const relative = path.relative(canonicalRoot, target);
  let current = canonicalRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) {
      fs.mkdirSync(current, { recursive: false });
    }
    assertRealDirectoryComponent(current, `Generated target ${relativeTarget}`);
    const canonicalComponent = canonicalExisting(current);
    const componentRelative = path.relative(canonicalRoot, canonicalComponent);
    if (
      componentRelative === ".." ||
      componentRelative.startsWith(`..${path.sep}`)
    ) {
      throw new Error(
        `Generated target resolves outside repository: ${relativeTarget}`,
      );
    }
  }
}

export function ensureGeneratedDirectory(root, relativeTarget) {
  const canonicalRoot = canonicalExisting(root);
  const target = resolveGeneratedTarget(canonicalRoot, relativeTarget);
  createDirectoryComponents(canonicalRoot, target, relativeTarget);
  fs.writeFileSync(
    path.join(target, GENERATED_MARKER),
    "centrald generated output\n",
    { flag: "w" },
  );
  return target;
}

export function cleanGeneratedDirectory(root, relativeTarget) {
  const target = resolveGeneratedTarget(root, relativeTarget);
  if (!fs.existsSync(target)) return false;
  const marker = path.join(target, GENERATED_MARKER);
  const targetStats = fs.lstatSync(target);
  const markerStats = fs.existsSync(marker) ? fs.lstatSync(marker) : null;
  if (
    targetStats.isSymbolicLink() ||
    !targetStats.isDirectory() ||
    markerStats === null ||
    markerStats.isSymbolicLink() ||
    !markerStats.isFile()
  ) {
    throw new Error(
      `Refusing cleanup without a regular ${GENERATED_MARKER}: ${relativeTarget}`,
    );
  }
  fs.rmSync(target, { recursive: true, force: false });
  return true;
}
