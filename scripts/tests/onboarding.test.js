import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("novice onboarding and advanced-control contract stays connected", () => {
  execFileSync(process.execPath, ["scripts/check-onboarding.js"], {
    cwd: process.cwd(),
    stdio: "pipe",
  });
});


test("recommended server setup keeps advanced PostgreSQL and custom-config paths explicit", () => {
  const wizard = fs.readFileSync(path.join(root, "crates/centrald-server/src/wizard.rs"), "utf8");
  const main = fs.readFileSync(path.join(root, "crates/centrald-server/src/main.rs"), "utf8");
  const services = fs.readFileSync(path.join(root, "crates/centrald-server/src/services.rs"), "utf8");
  assert.match(wizard, /Recommended: configure local PostgreSQL automatically/);
  assert.match(wizard, /Advanced: use an existing or remote PostgreSQL URL/);
  assert.doesNotMatch(main, /custom --config paths are unsupported/);
  assert.match(services, /loaded_config_revision/);
  assert.match(services, /redirect\(reqwest::redirect::Policy::none\(\)\)/);
});

test("managed local PostgreSQL setup is crash-recoverable before first mutation", () => {
  const recovery = fs.readFileSync(
    path.join(root, "crates/centrald-server/src/setup_recovery.rs"),
    "utf8",
  );
  const postgres = fs.readFileSync(
    path.join(root, "crates/centrald-server/src/local_postgres.rs"),
    "utf8",
  );
  const main = fs.readFileSync(
    path.join(root, "crates/centrald-server/src/main.rs"),
    "utf8",
  );
  assert.match(main, /begin_setup[\s\S]*provision_role/);
  assert.match(recovery, /boot_id[\s\S]*pid[\s\S]*start_ticks/);
  assert.match(recovery, /another centrald-server initial-setup process is still provisioning/);
  assert.match(recovery, /SetupPhase::Committed/);
  assert.match(postgres, /COMMENT ON ROLE/);
  assert.match(postgres, /shobj_description\(oid, 'pg_authid'\)/);
  assert.match(postgres, /database_owner/);
  assert.match(postgres, /drop_owned_role/);
  assert.match(postgres, /NOCREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION/);
  const journalFields = /struct SetupRecoveryJournal \{([\s\S]*?)\n\}/.exec(recovery)?.[1] ?? "";
  assert.doesNotMatch(journalFields, /password|database_url:\s|SecretString/);
  assert.match(recovery, /SetupDatabaseMode::External/);
  assert.match(recovery, /cleanup_external_database/);
});
