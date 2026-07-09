# Test suite

One `.tex` + compiled `.pdf` per case, built on the official
[USENIX Security '27 template](https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip)
(vendored in `template/`) with `lipsum` filler. Each source's header comment
states what it tests and the expected outcome; the name states the expectation:

- `good-*`: must report zero findings
- `warn-*`: passes with specific warning(s)
- `bad-*` : must fail with the named error

**Note.** The `*-squeeze-*` cases have no `.tex` source: they come from USENIX Security 2026
[disallowed squeezing examples](https://www.usenix.org/sites/default/files/disallowed-squeezing-examples.pdf)
deck, split one PDF per variant, with the deck's red banner labels redacted
out so only the trick itself is measured.

## Running

```
node run-tests.js     # checker vs committed PDFs (no LaTeX needed)
build.sh              # recompile from source (needs TeX Live)
```

## Adding tests

Adding a case: copy `sources/good-baseline.tex`, introduce exactly one
deviation (document it in the header), build, verify with `cli.js`, add to
`expected.json`, run the suite, commit the `.tex` (CI commits the `.pdf`).

## CI integration

PDFs are committed so the suite runs anywhere; CI rebuilds them from source on every push and commits refreshed PDFs whenever a source changed, then runs the checker against the fresh build.