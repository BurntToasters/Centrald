const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;

/**
 * Returns a reproducible RFC 3339 timestamp when release tooling supplies
 * CENTRALD_RELEASE_TIMESTAMP or SOURCE_DATE_EPOCH. Direct developer runs may
 * fall back to the current time.
 */
export function releaseTimestamp(environment = process.env) {
  const explicit = environment.CENTRALD_RELEASE_TIMESTAMP;
  if (explicit) {
    const milliseconds = Date.parse(explicit);
    if (!Number.isFinite(milliseconds)) {
      throw new Error(
        "CENTRALD_RELEASE_TIMESTAMP must be a valid RFC 3339 timestamp",
      );
    }
    return new Date(milliseconds).toISOString();
  }

  const epoch = environment.SOURCE_DATE_EPOCH;
  if (epoch !== undefined && epoch !== "") {
    if (!/^(?:0|[1-9]\d*)$/u.test(epoch)) {
      throw new Error(
        "SOURCE_DATE_EPOCH must be a non-negative integer number of seconds",
      );
    }
    const milliseconds = Number(epoch) * 1000;
    if (!Number.isSafeInteger(milliseconds)) {
      throw new Error(
        "SOURCE_DATE_EPOCH is outside the supported JavaScript date range",
      );
    }
    const date = new Date(milliseconds);
    if (Number.isNaN(date.valueOf())) {
      throw new Error("SOURCE_DATE_EPOCH is outside the supported date range");
    }
    return date.toISOString();
  }

  return new Date().toISOString();
}

/**
 * Compares two strict Semantic Versioning 2.0.0 values.
 * Build metadata is ignored for precedence as required by the specification.
 */
export function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (const field of ["major", "minor", "patch"]) {
    if (a[field] < b[field]) return -1;
    if (a[field] > b[field]) return 1;
  }

  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0;
  if (a.prerelease.length === 0) return 1;
  if (b.prerelease.length === 0) return -1;

  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftIdentifier = a.prerelease[index];
    const rightIdentifier = b.prerelease[index];
    if (leftIdentifier === undefined) return -1;
    if (rightIdentifier === undefined) return 1;
    const leftNumeric = /^\d+$/u.test(leftIdentifier);
    const rightNumeric = /^\d+$/u.test(rightIdentifier);
    if (leftNumeric && rightNumeric) {
      const leftNumber = BigInt(leftIdentifier);
      const rightNumber = BigInt(rightIdentifier);
      if (leftNumber < rightNumber) return -1;
      if (leftNumber > rightNumber) return 1;
      continue;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    if (leftIdentifier < rightIdentifier) return -1;
    if (leftIdentifier > rightIdentifier) return 1;
  }
  return 0;
}

export function parseSemver(value) {
  const match = SEMVER.exec(value);
  if (!match)
    throw new Error(
      `Invalid Semantic Versioning value ${JSON.stringify(value)}`,
    );
  const prerelease = match[4]?.split(".") ?? [];
  for (const identifier of prerelease) {
    if (
      /^\d+$/u.test(identifier) &&
      identifier.length > 1 &&
      identifier.startsWith("0")
    ) {
      throw new Error(
        `Numeric prerelease identifiers cannot contain leading zeroes: ${value}`,
      );
    }
  }
  return {
    major: BigInt(match[1]),
    minor: BigInt(match[2]),
    patch: BigInt(match[3]),
    prerelease,
  };
}
