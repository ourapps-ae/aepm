// Validate CycloneDX 1.6 JSON documents against the official schema files beside this script (ajv, draft-07).
// Usage: AJV_MODULES=<node_modules containing ajv and ajv-formats> node validate.mjs FILE...
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(resolve(process.env.AJV_MODULES), "noop.js"));
const Ajv = require("ajv").default;
const addFormats = require("ajv-formats").default;
const schema = (name) => JSON.parse(readFileSync(join(here, name), "utf8"));

const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
addFormats(ajv);
ajv.addSchema(schema("spdx.schema.json"), "spdx.schema.json");
ajv.addSchema(schema("jsf-0.82.schema.json"), "jsf-0.82.schema.json");
const validate = ajv.compile(schema("bom-1.6.schema.json"));
let failed = 0;
for (const file of process.argv.slice(2)) {
  const ok = validate(JSON.parse(readFileSync(file, "utf8")));
  if (!ok) failed++;
  console.log(JSON.stringify({ file, ok, errors: ok ? [] : validate.errors }));
}
process.exit(failed ? 1 : 0);
