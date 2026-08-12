import { run } from "./command.js";

for (const [command, args] of [
  ["npm", ["run", "check:onboarding"]],
  ["npm", ["run", "format:check"]],
  ["npm", ["run", "lint"]],
  ["npm", ["run", "typecheck"]],
  ["npm", ["test"]],
  ["npm", ["run", "test:rust"]],
]) {
  run(command, args);
}
