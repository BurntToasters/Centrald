import { run } from "./command.js";

for (const [command, args] of [
  ["npm", ["run", "check:onboarding"]],
  ["npm", ["run", "format:check"]],
  ["npm", ["run", "lint"]],
  ["npm", ["run", "typecheck"]],
  ["npm", ["--prefix", "site", "run", "check"]],
  ["npm", ["--prefix", "site", "run", "build"]],
  ["npm", ["test"]],
  ["npm", ["run", "test:rust"]],
]) {
  run(command, args);
}
