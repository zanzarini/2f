// Checks this SDK against the random corpus written by the Rust core.
// Run through scripts/crosscheck.sh.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { actionHash, bindingHash, canonical } from "./index.js";

const corpus = JSON.parse(readFileSync(new URL("../corpus.json", import.meta.url), "utf8"));
let checked = 0;
const fail = (what, got, want, source) => {
  console.error(`MISMATCH ${what}\n  got:  ${got}\n  want: ${want}\n  from: ${JSON.stringify(source).slice(0, 300)}`);
  process.exit(1);
};

for (const { value, canonical: want } of corpus.values) {
  const got = canonical(value);
  if (got !== want) fail("canonical(value)", got, want, value);
  checked++;
}
for (const entry of corpus.actions) {
  const text = canonical(entry.action);
  if (text !== entry.canonical) fail("canonical(action)", text, entry.canonical, entry.action);
  const hash = actionHash(entry.action);
  if (hash !== entry.hash) fail("actionHash", hash, entry.hash, entry.action);
  const binding = bindingHash(entry.binding).toString("base64url");
  if (binding !== entry.binding_hash) fail("bindingHash", binding, entry.binding_hash, entry.binding);
  const reject = createHash("sha256").update("2F-REJECT-v1\n").update(canonical(entry.binding), "utf8").digest("base64url");
  if (reject !== entry.reject_hash) fail("reject hash", reject, entry.reject_hash, entry.binding);
  checked++;
}
console.log(`typescript agrees with rust on ${checked} random cases`);
