# USENIX Security '27 PDF format compliance checker

Checks a submission PDF against the formatting requirements in the
[USENIX Security '27 Call for Papers](https://www.usenix.org/conference/usenixsecurity27/call-for-papers).
The same code runs for authors and chairs.

> **Pre-release prototype.** This checker is meant to *help* authors and
> chairs, not to gatekeep: it measures the rendered PDF and can have false
> positives, and the submission form will include a text field to briefly
> explain any finding that does not apply to your paper. Comments and
> feedback are very welcome:
> [jo.vanbulck@kuleuven.be](mailto:jo.vanbulck@kuleuven.be).

- **Browser**: drop your PDF on the page. Runs fully client-side (MuPDF
  WebAssembly in a Web Worker): the PDF never leaves your machine.
- **CLI** (Node 18+, nothing to install):

  ```
  node cli.js paper.pdf            # exit 0 = clean, 1 = warnings only, 2 = errors
  node cli.js *.pdf --json         # batch mode, one JSON line per file
  ```

- Local hosting: any static file server in the repo root, e.g.
  `python3 -m http.server`.

## Checks

| rule            | requirement (CFP)     | measured                                                                           | level                             |
|-----------------|-----------------------|------------------------------------------------------------------------------------|-----------------------------------|
| `page-size`     | U.S. letter           | page box 8.5" × 11" (± 2 pt)                                                       | ❌ error                          |
| `text-block`    | text block ≤ 7" × 9"  | 7" × 9" (+ 0.1") window best-fit per document; a few scattered overflows (wide table, long URL/code line, bleeding graphic) warn, a systematic enlargement (most pages, or a page mostly outside) errors | ⚠️ warning (❌ error if systematic) |
| `font-size`     | 10 pt body text       | dominant char size on body pages ≥ 9.6 pt                                          | ❌ error (⚠️ < 9.9)               |
| `font-family`   | Times Roman           | dominant font is a Times variant                                                   | ⚠️ warning                        |
| `leading`       | 12 pt leading         | dominant baseline distance ≥ 11.6 pt, per body page                                | ❌ error (⚠️ < 11.9)              |
| `two-column`    | two-column format     | ≥ 60 % of lines in one half-page                                                   | ⚠️ warning                        |
| `heading-space` | no whitespace removal | ≥ 2 headings with < 10.5 pt above (template ~13.7 pt)                              | ❌ error                          |
| `title-space`   | no whitespace removal | whitespace below the page-1 title ≥ 12 pt (template ~30 pt)                        | ❌ error (⚠️ < 24)                |
| `front-matter`  | front matter not squeezed | page-1 body (abstract) starts ~3.5" down; far above = title/author space trimmed (empty author block is fine) | ❌ error (⚠️ if mild)             |
| `anonymity`     | anonymous submission  | author block has an "Anonymous…"-style marker; names, affiliations, e-mail flagged | ⚠️ warning                        |
| `page-limit`    | body ≤ 13 pages       | body ends where the first appendix / References heading begins; must fit 13 pages (a heading at the top of page 14 = exactly 13 pages is fine; appendices don't count) | ❌ error (⚠️ if no such heading) |
| `open-science`  | required appendix     | "Open Science" heading present                                                     | ❌ error                          |
| `ethics`        | encouraged appendix   | an "Ethics…"-style heading present                                                 | ⚠️ warning                        |
| `metadata`      | anonymous submission  | no author name in PDF metadata                                                     | ❌ error                          |

Lines with < 5 visible characters (page numbers, listing gutters) are stray
marks: excluded from the text block, covered by the graphics check instead.

## Source code organization

```
.
├── checker.js       policy (RULES) checks
├── cli.js           command-line front end
├── index.html       web front end (+ ui.js, style.css, worker.js)
├── vendor/mupdf/    pinned unmodified MuPDF.js WASM build (AGPL)
└── tests/           known-good/-bad PDF and LaTeX papers
```
