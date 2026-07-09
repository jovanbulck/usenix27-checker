#!/usr/bin/env node
// Command-line front end for checker.js.
//
// Usage:  node cli.js paper.pdf [more.pdf ...] [--json]
//
// Exit code: the worst outcome across all files --
//   0  every file is fully clean (no findings at all)
//   1  warnings only
//   2  at least one error
// Requires Node 18+; no npm install needed (MuPDF is vendored).

import { readFileSync } from "node:fs";
import { checkPdf, formatReport } from "./checker.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
const files = args.filter((a) => a !== "--json");

if (files.length === 0) {
  console.error("usage: node cli.js paper.pdf [more.pdf ...] [--json]");
  process.exit(2);
}

let worst = 0;
for (const file of files) {
  let data;
  try {
    data = readFileSync(file);
  } catch (exc) {
    console.log(`== ${file}\n   ERROR   cannot read file: ${exc.message}`);
    worst = 2;
    continue;
  }
  const result = checkPdf(data);
  const errors = result.findings.some((f) => f.level === "error");
  worst = Math.max(worst, errors ? 2 : result.findings.length ? 1 : 0);
  if (json) {
    console.log(JSON.stringify({ file, ...result }));
  } else {
    console.log(formatReport(file, result));
  }
}
process.exit(worst);
