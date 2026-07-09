#!/usr/bin/env node
// Test runner: checks every PDF in tests/pdfs/ against tests/expected.json.
//
//   node tests/run-tests.js
//
// Exit code 0 when every case matches its expectation. See tests/README.md
// for how to add a case.

import { readFileSync } from "node:fs";
import { checkPdf } from "../checker.js";

const here = (p) => new URL(p, import.meta.url);
const { cases } = JSON.parse(readFileSync(here("expected.json"), "utf8"));

// findings as comparable "level rule" strings
const key = ([level, rule]) => `${level} ${rule}`;
const got = (result) => result.findings.map((f) => key([f.level, f.rule]));

let failed = 0;
for (const spec of cases) {
  const result = checkPdf(readFileSync(here(`pdfs/${spec.name}.pdf`)));
  const problems = [];

  if (result.ok !== spec.ok) {
    problems.push(`verdict: expected ok=${spec.ok}, got ok=${result.ok}`);
  }
  if (spec.findings) { // exact multiset of findings
    const expected = spec.findings.map(key).sort();
    const actual = got(result).sort();
    if (JSON.stringify(expected) !== JSON.stringify(actual)) {
      problems.push(`findings: expected [${expected}], got [${actual}]`);
    }
  }
  for (const pair of spec.must || []) { // required findings, extras allowed
    if (!got(result).includes(key(pair))) {
      problems.push(`missing required finding: ${key(pair)}`);
    }
  }

  if (problems.length === 0) {
    console.log(`PASS ${spec.name}  (${spec.purpose})`);
  } else {
    failed++;
    console.log(`FAIL ${spec.name}  (${spec.purpose})`);
    for (const p of problems) console.log(`     ${p}`);
    for (const f of result.findings) {
      console.log(`     reported: ${f.level} [${f.rule}] ${f.message}`);
    }
  }
}

console.log(`\n${cases.length - failed}/${cases.length} cases pass`);
process.exit(failed ? 1 : 0);
