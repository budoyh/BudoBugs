import { runReadOnlyTask } from "./index.js";

if (process.argv.includes("--help")) {
  process.stdout.write("BudoBugs Codex SDK smoke: imports the pinned SDK; no model call is made.\n");
} else {
  // Referencing the exported function proves the bundled SDK surface loads without
  // issuing a model request or requiring a credential in CI.
  process.stdout.write(`${typeof runReadOnlyTask === "function" ? "PASS" : "FAIL"}\n`);
}
