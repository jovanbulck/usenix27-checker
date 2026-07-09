// Format compliance checker for USENIX Security '27 submissions.
//
// Measures the geometry of a submitted PDF against the CFP formatting
// requirements: every threshold is published in RULES below and includes
// a generous tolerance.
//
// The same file runs in the browser (see worker.js) and under Node
// (see cli.js); in both cases the PDF is analyzed locally and never
// uploaded anywhere. PDF parsing is done by MuPDF (vendor/mupdf/, a
// pinned, unmodified copy of Artifex's official WebAssembly build).
//
// All coordinates are in PDF points (72 per inch) with the origin at the
// TOP-LEFT of the page, x growing right and y growing down, as delivered
// by MuPDF. A box is {x0, y0, x1, y1} with (x0, y0) the top-left corner.
import * as mupdf from "./vendor/mupdf/mupdf.js";

import { VERSION } from "./version.js";
export { VERSION };
export const IN = 72.0; // PDF points per inch

// --- the CFP formatting policy -------------------------------------------

export const RULES = Object.freeze({
  pageW: 8.5 * IN,          // U.S. letter
  pageH: 11 * IN,
  pageTol: 2.0,             // +/- tolerance allowed for PDF toolchains

  blockW: 7 * IN,           // maximum text block, best-fit once per
  blockH: 9 * IN,           // document (see fitWindow)
  blockTol: 0.1 * IN,
  graphicsTol: 0.25 * IN,   // graphics may bleed a bit further

  bodyPages: 13,            // main body before References

  fontPt: 10,               // body text nominal size
  fontRendered: 9.96,       // what LaTeX renders for 10 pt Times
  fontErr: 9.6,
  fontWarn: 9.9,

  leadingPt: 12,            // single-spaced baselines, per page
  leadingErr: 11.6,         // (savetrees moderate: 11.4)
  leadingWarn: 11.9,

  headingGap: 10.5,         // min whitespace above a heading; template
                            // >= ~12.6, titlesec abuse ~6-8
  titleGapPt: 30,           // whitespace below the page-1 title; the
  titleGapErr: 12,          // template's \maketitle leaves ~29.8 pt,
  titleGapWarn: 24,         // savetrees ~7
  bodyStartPt: 3.5 * IN,    // the template's front matter (title + author
  bodyStartErr: 2.2 * IN,   // block) reserves the top ~3.5"; the body (its
  bodyStartWarn: 2.8 * IN,  // abstract) begins there. Far above = squeezed.

  sections: [               // appendices (see CFP), placed after the main
                            // body and before References; they do NOT count
                            // toward the page limit (checkPageLimit ends the
                            // body at the first of these or References).
                            // [rule id, heading, detection regex, required?]
                            // (missing: required -> error, else warning)
    ["open-science", "Open Science", /open science/i, true],
    ["ethics", "Ethics / Ethical Considerations", /ethic/i, false],
  ],
});

// --- detection heuristics (how we recognize things, not what the CFP says) ---

const MIN_LINE_CHARS = 5;    // shorter lines (page/listing numbers) are stray marks
const HEADING_BUMP = 0.8;    // a heading is bold or this much larger than body text
const WINDOW_SLACK = 2.0;    // ignore sub-2pt excursions outside the text block
const LIMIT_TOP_SLACK = 18;  // a body-end heading up to ~1.5 lines below the
                             // block top still counts as the top of the next
                             // page (body used exactly the page budget)
const CULPRIT_SHARE = 0.25;  // more offending lines than this share of a page
                             // means the whole page overflows, not a few lines
const SYSTEMIC_PAGES = 3;    // an enlarged block overflows on more than this
const SYSTEMIC_FRAC = 0.5;   // many pages AND more than half of them: that is
                             // a systematic block enlargement (error); a few
                             // scattered overflows (a table, a URL) only warn
const MIN_WHOLE = 10;        // a page counts as over-full (error) only if at
                             // least this many lines overflow -- a high share
                             // on a sparse page (a wide table) does not
const BODY_TOL = 0.5;        // sizes within this of the dominant size are body text
const LEAD_MIN = 6;          // baseline gaps in this range sample the leading;
const LEAD_MAX = 20;         // anything else is a paragraph break
const MIN_GAPS = 8;          // don't judge a page's leading on fewer samples
const PROSE_MIN_FRAC = 0.33; // leading is sampled only below a line at least
                             // this fraction of the text-block width (prose,
                             // not narrow table/figure cells)
const MIN_SQUEEZED = 2;      // one compressed heading may be a false positive
const COLUMN_SHARE = 0.6;    // lines that must sit in one half of the page
const TITLE_MIN = 13, TITLE_MAX = 17; // the \Large title is ~14.3 pt
const MERGE_GAP = 16;        // fragments this close share a visual row (the
                             // template's column gutter is ~21 pt)

const TIMES_RE = /times|nimbus|termes|stix|ptmr|txr/i;
const BOLD_RE = /bold|medi|heavy|black/i; // Nimbus bold = "-Medi"
const REFS_RE = /^\s*(\d{1,2}|[A-Za-z])?[.\s]*(references|bibliography)\s*$/i;
const SECTION_RE = new RegExp(
  // a numbered heading is "N[.N] Word" whose word starts with a capital
  // (Title or Sentence case); the uppercase letter after the number keeps out
  // numbered pseudocode/algorithm lines ("8 end", "15 end")
  "^(\\d{1,2}(\\.\\d{1,2})*[.\\s]+[A-Z]|Abstract\\b|Acknowledg|Availability\\b|" +
  "References\\b|Bibliography\\b|Appendix\\b|Ethic|Open Science)");
const ABSTRACT_RE = /^Abstract\b/;
const ANON_RE = /anonym|blind|redact|omitt|under (review|submission)|(paper|submission)\s*(#|no\b|number|id)/i;
// the unfilled USENIX template author block ("Your N. Here", "Your
// Institution", "Second Name", "Second Institution"): an unfilled template,
// not a deanonymization risk, so it must not trip the anonymity check
const PLACEHOLDER_RE = /\byour (n\b|institution)|\bsecond (name|institution)|\bname institution\b/i;
const AFFIL_RE = /universit|institut|college|laborator|department|school|academ|polytech|\.edu\b|\.ac\.|@/i;

// --- author-facing messages and levels -------------------------------------
// Everything an author can see -- each finding's rule id, its error/warning
// level, and its message -- in one reviewable place. `level` and `rule` are
// strings, or functions of the measured values where the outcome depends on
// how bad the measurement is (the thresholds themselves live in RULES).
// The checks below only measure and call report().

const MESSAGES = {
  "page-size": {
    rule: "page-size",
    level: "error",
    text: ({ n, w, h, r }) =>
      `${n} page(s) are ${(w / IN).toFixed(2)}" x ${(h / IN).toFixed(2)}", ` +
      `not U.S. letter (${num(r.pageW / IN)}" x ${num(r.pageH / IN)}")`,
  },

  // a few isolated overflows (a wide table, a long code line or URL, a figure
  // bleeding out) are honest mistakes -> warning; overflow spread across many
  // pages is a systematic block enlargement -> error (systematic is set true).
  "text-block-lines": {
    rule: "text-block",
    level: ({ systematic }) => (systematic ? "error" : "warning"),
    text: ({ page, n, text, out, wide, tall, r }) =>
      `page ${page}: ${n} line(s) near "${text.slice(0, 40)}" fall ` +
      `${out.toFixed(0)} pt outside the ${blockStr(r)} text block ` +
      `(+${num(r.blockTol / IN)}" tolerance); ` +
      (!tall ? "an over-wide table, listing, or figure?"
        : !wide ? "text above or below the block: a header/footer, or " +
                  "squeezed-in lines?"
        : "content outside the block"),
  },

  // most of the page's lines are outside the block: that page is over-full
  "text-block-page": {
    rule: "text-block",
    level: "error",
    text: ({ page, w, h, r }) =>
      `page ${page}: text spans ${(w / IN).toFixed(2)}" x ` +
      `${(h / IN).toFixed(2)}", exceeding the ${blockStr(r)} text block ` +
      `(+${num(r.blockTol / IN)}" tolerance)`,
  },

  "text-block-graphics": {
    rule: "text-block",
    level: "warning",
    text: ({ page, w, h, r }) =>
      `page ${page}: content including graphics is ${(w / IN).toFixed(2)}" x ` +
      `${(h / IN).toFixed(2)}", exceeds the ${blockStr(r)} text block ` +
      `(+${num(r.graphicsTol / IN)}" tolerance)`,
  },

  "font-size": {
    rule: "font-size",
    level: ({ size, r }) => (size < r.fontErr ? "error" : "warning"),
    text: ({ size, r }) => (size < r.fontErr
      ? `dominant font size is ${num(size)} pt; the template sets body text ` +
        `at ${num(r.fontPt)} pt (measured as ~${num(r.fontRendered)} pt)`
      : `dominant font size is ${num(size)} pt, slightly below the expected ` +
        `~${num(r.fontRendered)} pt; please verify`),
  },

  "font-family": {
    rule: "font-family",
    level: "warning",
    text: ({ font }) =>
      `dominant font '${font}' is not a recognized Times variant; please verify`,
  },

  "leading": {
    rule: "leading",
    level: ({ sample, r }) => (sample < r.leadingErr ? "error" : "warning"),
    text: ({ pages, sample, r }) =>
      `line spacing on page(s) ${pageList(pages)} is` +
      `${sample < r.leadingErr ? "" : " slightly"} below the ` +
      `${num(r.leadingPt)} pt the template sets (e.g. ${num(sample)} pt on ` +
      `page ${pages[0]}; \\linespread or savetrees-style hacks?)`,
  },

  "two-column": {
    rule: "two-column",
    level: "warning",
    text: () =>
      "the layout does not look two-column; please verify against the template",
  },

  "heading-space": {
    rule: "heading-space",
    level: "error",
    text: ({ n, pages }) =>
      `${n} section headings on page(s) ${pageList(pages)} have compressed ` +
      "whitespace above them (titlesec/savetrees-style hacks?)",
  },

  "title-space": {
    rule: "title-space",
    level: ({ gap, r }) => (gap < r.titleGapErr ? "error" : "warning"),
    text: ({ gap, r }) =>
      `page 1: only ${gap.toFixed(1)} pt of whitespace below the title; the ` +
      `template leaves ~${num(r.titleGapPt)} pt (space-around-title trimming?)`,
  },

  "front-matter": {
    rule: "front-matter",
    level: ({ top, r }) => (top < r.bodyStartErr ? "error" : "warning"),
    text: ({ top, r }) =>
      `page 1: the body starts only ${(top / IN).toFixed(2)}" from the top; the ` +
      `template's title block reserves ~${num(r.bodyStartPt / IN)}" ` +
      "(front matter squeezed with negative space or savetrees?)",
  },

  "anonymity": {
    rule: "anonymity",
    level: "warning",
    text: ({ text, affil }) =>
      `the author block ("${text.slice(0, 40)}") does not look anonymized` +
      (affil ? " and appears to name an affiliation or e-mail address" : "") +
      "; submissions should be anonymized -- use e.g. 'Anonymous Submission'",
  },

  "page-limit-unknown": {
    rule: "page-limit",
    level: "warning",
    text: ({ r }) =>
      "no References or appendix heading found; the " +
      `${r.bodyPages}-page main-body limit could not be verified`,
  },

  "page-limit-exceeded": {
    rule: "page-limit",
    level: "error",
    text: ({ text, page, r }) =>
      `the main body must fit in ${r.bodyPages} pages, but it runs onto ` +
      `page ${page}, where "${text.slice(0, 30)}" (its first end heading) begins`,
  },

  "section-missing": {
    rule: ({ rule }) => rule,
    level: ({ required }) => (required ? "error" : "warning"),
    text: ({ title, required }) =>
      `no '${title}' section heading found; this appendix is ` +
      `${required ? "required" : "strongly encouraged where applicable"} ` +
      "(see CFP)",
  },

  "metadata": {
    rule: "metadata",
    level: "error",
    text: ({ author }) =>
      `PDF metadata contains an author name ('${author}'); submissions should be ` +
      "anonymized",
  },

  "parse": {
    rule: "parse",
    level: "error",
    text: ({ verb, error }) =>
      `could not ${verb} PDF: ${error}; contact the chairs if you believe ` +
      "the file is valid",
  },
};

// Build the finding for MESSAGES[key] from the measured values.
function report(key, params = {}, loc = {}) {
  const spec = MESSAGES[key];
  const resolve = (v) => (typeof v === "function" ? v(params) : v);
  return finding(resolve(spec.level), resolve(spec.rule),
                 spec.text(params), loc);
}

// --- small helpers ------------------------------------------------------------

// Format a number for a message: 7 stays "7", 9.96 stays "9.96".
function num(v) {
  return String(Math.round(v * 1000) / 1000);
}

function blockStr(r) {
  return `${num(r.blockW / IN)}" x ${num(r.blockH / IN)}"`;
}

// Tally occurrences (a Counter): tally(map, key, count) then mode(map).
function tally(map, key, count = 1) {
  map.set(key, (map.get(key) || 0) + count);
}

function mode(map) {
  let best, bestCount = -1;
  for (const [key, count] of map) {
    if (count > bestCount) [best, bestCount] = [key, count];
  }
  return best;
}

function total(map) {
  let sum = 0;
  for (const count of map.values()) sum += count;
  return sum;
}

// Smallest box covering both `b` and `a` (which may be null).
function union(a, b) {
  if (!a) return { x0: b.x0, y0: b.y0, x1: b.x1, y1: b.y1 };
  return { x0: Math.min(a.x0, b.x0), y0: Math.min(a.y0, b.y0),
           x1: Math.max(a.x1, b.x1), y1: Math.max(a.y1, b.y1) };
}

function asList(box) {
  return box ? [box.x0, box.y0, box.x1, box.y1] : null;
}

function pageList(pages) {
  return [...pages].sort((a, b) => a - b).join(", ");
}

// --- geometry extraction ------------------------------------------------------
// A Line is {page, text, x0, y0, x1, y1, baseline, size, font, chars} where
// size and font are the dominant character size and font name on the line and
// chars counts its non-whitespace characters. A "solid" line has at least
// MIN_LINE_CHARS of them: stray marks (page numbers, listing-gutter digits)
// are not solid and do not define the text block.

function solid(line) {
  return line.chars >= MIN_LINE_CHARS;
}

// Walk one page's structured text. Returns the page's lines, the baseline
// gaps [gap, size above, size below] between consecutive lines of each
// block, and the page's character-size and font-name tallies.
function extractText(page, pageno) {
  const lines = [], gaps = [], sizes = new Map(), fonts = new Map();
  let cur = null, prev = null;

  const finishLine = () => {
    if (!cur || total(cur.sizes) === 0) { cur = null; return; }
    const line = {
      page: pageno, text: cur.text.trim(),
      x0: cur.x0, y0: cur.y0, x1: cur.x1, y1: cur.y1,
      baseline: mode(cur.baselines),
      size: mode(cur.sizes), font: mode(cur.fonts),
      nfonts: cur.fonts.size,  // 1 = uniformly styled row (see isHeading)
      chars: cur.text.replace(/\s/g, "").length,
    };
    for (const [size, count] of cur.sizes) tally(sizes, size, count);
    for (const [font, count] of cur.fonts) tally(fonts, font, count);
    if (prev && line.baseline - prev.baseline >= LEAD_MIN
             && line.baseline - prev.baseline <= LEAD_MAX) {
      // 4th field: width of the line above, so leading can be sampled from
      // prose lines only and not from narrow table/figure cells (bodyGaps)
      gaps.push([Math.round((line.baseline - prev.baseline) * 10) / 10,
                 prev.size, line.size, prev.x1 - prev.x0]);
    }
    lines.push(line);
    prev = line;
    cur = null;
  };

  page.toStructuredText().walk({
    beginTextBlock() { prev = null; },     // gaps are measured within a block
    beginLine() { cur = { text: "", x0: Infinity, y0: Infinity, x1: -Infinity,
                          y1: -Infinity, sizes: new Map(), fonts: new Map(),
                          baselines: new Map() }; },
    onChar(char, origin, font, size, quad) {
      if (!cur) return;
      cur.text += char;
      if (char.trim() === "") return;      // whitespace has no geometry to keep
      tally(cur.sizes, Math.round(size * 10) / 10);
      tally(cur.fonts, font.getName());
      tally(cur.baselines, Math.round(origin[1] * 10) / 10);
      const [ulx, uly, urx, ury, llx, lly, lrx, lry] = quad;
      cur.x0 = Math.min(cur.x0, ulx, llx);
      cur.y0 = Math.min(cur.y0, uly, ury);
      cur.x1 = Math.max(cur.x1, urx, lrx);
      cur.y1 = Math.max(cur.y1, lly, lry);
    },
    endLine: finishLine,
    endTextBlock: finishLine,
  });
  return { lines, gaps, sizes, fonts };
}

// MuPDF splits a visual row into separate lines at large horizontal gaps
// (e.g. a section heading arrives as "1" plus "Introduction"). Rejoin
// fragments in the same font and size that share a baseline and sit within
// MERGE_GAP of each other, so lines read the way authors see them. The
// column gutter is wider than MERGE_GAP and stays unmerged, and so do
// unrelated neighbors like a code listing's tiny gutter numbers next to
// the code itself (different font size).
function mergeRows(lines) {
  const sorted = [...lines].sort((a, b) => (a.baseline - b.baseline) || (a.x0 - b.x0));
  const merged = [];
  for (const line of sorted) {
    const last = merged[merged.length - 1];
    const gap = last ? line.x0 - last.x1 : Infinity;
    if (last && Math.abs(line.baseline - last.baseline) < 0.6
             && gap > -2 && gap < MERGE_GAP
             && Math.abs(line.size - last.size) <= 0.3 && line.font === last.font) {
      last.text += " " + line.text;
      if (line.chars > last.chars) { // the longer fragment sets size and font
        last.size = line.size;
        last.font = line.font;
      }
      last.nfonts = Math.max(last.nfonts, line.nfonts);
      last.chars += line.chars;
      last.x1 = Math.max(last.x1, line.x1);
      last.y0 = Math.min(last.y0, line.y0);
      last.y1 = Math.max(last.y1, line.y1);
    } else {
      merged.push({ ...line });
    }
  }
  return merged;
}

// Collect the bounding box of every drawing and image on the page by
// replaying its content stream into a device that only records geometry.
function extractGraphics(page, width, height) {
  const gfx = [];
  // Active clip rectangles, innermost last. Plot data often extends past
  // its axes and is clipped away in the PDF: without intersecting against
  // the clip, such invisible content inflates a figure's bounds (seen in
  // the wild reaching y=0). Only recorded bounds are clipped; the stack
  // must stay balanced, so unknown clip shapes push a non-narrowing entry.
  const clips = [];
  const clip = () => (clips.length ? clips[clips.length - 1] : null);
  const pushClip = (rect) => {
    const c = clip();
    clips.push(c ? [Math.max(rect[0], c[0]), Math.max(rect[1], c[1]),
                    Math.min(rect[2], c[2]), Math.min(rect[3], c[3])] : rect);
  };
  const record = (rect) => {
    const c = clip() || [0, 0, width, height];
    const box = { x0: Math.max(rect[0], c[0], 0),
                  y0: Math.max(rect[1], c[1], 0),
                  x1: Math.min(rect[2], c[2], width),
                  y1: Math.min(rect[3], c[3], height) };
    if (box.x1 > box.x0 && box.y1 > box.y0) gfx.push(box);
  };
  const plainStroke = new mupdf.StrokeState(
    { lineCap: "Butt", lineJoin: "Miter", lineWidth: 1, miterLimit: 10 });
  const pathRect = (path, stroke, ctm) =>
    mupdf.Rect.transform(path.getBounds(stroke, mupdf.Matrix.identity), ctm);
  const unitRect = (ctm) => {            // the unit square under `ctm`
    const xs = [ctm[4], ctm[0] + ctm[4], ctm[2] + ctm[4], ctm[0] + ctm[2] + ctm[4]];
    const ys = [ctm[5], ctm[1] + ctm[5], ctm[3] + ctm[5], ctm[1] + ctm[3] + ctm[5]];
    return [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)];
  };
  const device = new mupdf.Device({
    fillPath(path, evenOdd, ctm) { record(pathRect(path, plainStroke, ctm)); },
    strokePath(path, stroke, ctm) { record(pathRect(path, stroke, ctm)); },
    fillImage(image, ctm) { record(unitRect(ctm)); },
    fillImageMask(image, ctm) { record(unitRect(ctm)); },
    fillShade(shade, ctm) { record(unitRect(ctm)); },
    clipPath(path, evenOdd, ctm) { pushClip(pathRect(path, plainStroke, ctm)); },
    clipStrokePath(path, stroke, ctm) { pushClip(pathRect(path, stroke, ctm)); },
    clipImageMask(image, ctm) { pushClip(unitRect(ctm)); },
    clipText() { pushClip(clip() || [0, 0, width, height]); },
    clipStrokeText() { pushClip(clip() || [0, 0, width, height]); },
    popClip() { clips.pop(); },
  });
  page.run(device, mupdf.Matrix.identity);
  device.close();
  return gfx;
}

// The text lines that count on a page (see `solid`).
function solidLines(page) {
  return page.lines.filter(solid);
}

// Union of a page's solid text lines; null if there are none.
function textBBox(page) {
  return solidLines(page).reduce((box, l) => union(box, l), null);
}

// All content on a page, graphics included; null on a blank page.
function contentBBox(page) {
  return page.gfx.reduce((box, g) => union(box, g), textBBox(page));
}

// Best-fit interval [t, t + length] covering the most {lo, hi} spans.
//
// All pages of a document share one layout, so the text block is placed
// once per document: lines outside this window on any page are violations
// (a per-page box could slide down and swallow a footer on short pages).
function fitWindow(spans, length) {
  const los = spans.map((s) => s.lo).sort((a, b) => a - b);
  const his = spans.map((s) => s.hi).sort((a, b) => a - b);
  // binary search: how many values in `sorted` satisfy value <op> v
  const count = (sorted, v, op) => {
    let lo = 0, hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (op(sorted[mid], v)) lo = mid + 1; else hi = mid;
    }
    return lo;
  };
  // a span [lo, hi] lies inside [t, t + length] iff lo >= t and hi <= t+length
  const covered = (t) => count(his, t + length, (a, b) => a <= b)
                       - count(los, t, (a, b) => a < b);
  // the optimum has a span edge on one of the window's edges
  const candidates = [...new Set([...los, ...his.map((h) => h - length)])]
    .sort((a, b) => a - b);
  let bestT = 0, bestN = -1;
  for (const t of candidates) {
    const n = covered(t);
    if (n > bestN) [bestT, bestN] = [t, n]; // topmost placement wins ties
  }
  return { lo: bestT, hi: bestT + length };
}

// Analyze an opened MuPDF document into the plain facts the checks need:
//   { pages: [{number, width, height, lines, gaps, gfx}],
//     bodySize, bodyFont, author, window }
// Throws if the file has no extractable text.
export function analyze(doc, rules) {
  const sizes = new Map(), fonts = new Map();
  const pages = [];
  for (let i = 0; i < doc.countPages(); i++) {
    const page = doc.loadPage(i);
    const [x0, y0, x1, y1] = page.getBounds();
    const width = x1 - x0, height = y1 - y0;
    const text = extractText(page, i + 1);
    for (const [size, count] of text.sizes) tally(sizes, size, count);
    for (const [font, count] of text.fonts) tally(fonts, font, count);
    pages.push({ number: i + 1, width, height,
                 lines: mergeRows(text.lines), gaps: text.gaps,
                 sizes: text.sizes, fonts: text.fonts,
                 gfx: extractGraphics(page, width, height) });
    page.destroy();
  }
  if (sizes.size === 0) {
    throw new Error("no text found (scanned or image-only file?)");
  }
  const all = pages.flatMap(solidLines);
  const window = all.length
    ? { x: fitWindow(all.map((l) => ({ lo: l.x0, hi: l.x1 })),
                     rules.blockW + rules.blockTol),
        y: fitWindow(all.map((l) => ({ lo: l.y0, hi: l.y1 })),
                     rules.blockH + rules.blockTol) }
    : { x: { lo: 0, hi: rules.pageW }, y: { lo: 0, hi: rules.pageH } };
  const result = { pages, bodySize: mode(sizes), bodyFont: mode(fonts),
                   author: doc.getMetaData("info:Author"), window,
                   bodyEnd: null,                  // first refs/appendix heading
                   bodyEndPage: pages.length + 1 };
  // Font and leading rules apply to the MAIN BODY: a long bibliography,
  // appendix listings, or tables may legitimately use denser text and must
  // not skew the dominant size. Locate the end of the body (first of
  // References or an appendix heading, found with the document-wide guess)
  // and re-derive the dominant size and font from the body pages only.
  const markers = [REFS_RE, ...rules.sections.map(([, , pattern]) => pattern)]
    .map((pattern) => findHeading(result, pattern)).filter(Boolean);
  if (markers.length) {
    result.bodyEnd = markers.reduce((a, b) =>
      b.page < a.page || (b.page === a.page && b.y0 < a.y0) ? b : a);
    result.bodyEndPage = result.bodyEnd.page;
    if (result.bodyEndPage > 1) {
      const bodySizes = new Map(), bodyFonts = new Map();
      for (const p of pages.slice(0, result.bodyEndPage - 1)) {
        for (const [size, count] of p.sizes) tally(bodySizes, size, count);
        for (const [font, count] of p.fonts) tally(bodyFonts, font, count);
      }
      if (bodySizes.size) {
        result.bodySize = mode(bodySizes);
        result.bodyFont = mode(bodyFonts);
      }
    }
  }
  return result;
}

// (page, gap) between consecutive body-text baselines, on body pages only.
// Gaps next to footnote- or table-sized text are excluded, and pages after
// the one where the bibliography/appendices start are free (see analyze;
// the marker page itself still holds body text above the heading), so
// legitimately denser text cannot skew the line-spacing measurement.
function bodyGaps(doc) {
  const result = [];
  const proseWidth = PROSE_MIN_FRAC * (doc.window.x.hi - doc.window.x.lo);
  for (const p of doc.pages) {
    if (p.number > doc.bodyEndPage) continue;
    for (const [gap, above, below, wAbove] of p.gaps) {
      if (Math.abs(above - doc.bodySize) <= BODY_TOL
          && Math.abs(below - doc.bodySize) <= BODY_TOL
          && wAbove >= proseWidth) {  // skip narrow table/figure cells
        result.push([p.number, gap]);
      }
    }
  }
  return result;
}

// Never smaller than body text (rules out bold keywords in 8 pt listings).
function isHeading(doc, line) {
  return line.size >= doc.bodySize + HEADING_BUMP
      || (line.size >= doc.bodySize - BODY_TOL && BOLD_RE.test(line.font));
}

// First line matching `pattern` that looks like a section heading.
function findHeading(doc, pattern) {
  for (const p of doc.pages) {
    for (const l of p.lines) {
      if (pattern.test(l.text) && l.text.length < 60 && isHeading(doc, l)) {
        return l;
      }
    }
  }
  return null;
}

// --- the checks: each takes (doc, rules) and returns a list of findings ------
// -----------------------------------------------------------------------------

export function finding(level, rule, message,
                        { page = null, bbox = null, pages = null,
                          boxes = null } = {}) {
  return { level, rule, message, page, bbox,
           pages: pages ? [...pages].sort((a, b) => a - b) : null,
           boxes }; // multi-page highlights: [[page, [x0, y0, x1, y1]], ...]
}

// Pages must be U.S. letter.
function checkPageSize(doc, r) {
  const bad = doc.pages.filter((p) => Math.abs(p.width - r.pageW) > r.pageTol
                                   || Math.abs(p.height - r.pageH) > r.pageTol);
  if (!bad.length) return [];
  return [report("page-size",
    { n: bad.length, w: bad[0].width, h: bad[0].height, r },
    { page: bad[0].number })];
}

// Text must fit the block window placed once per document. A few isolated
// overflows (a wide table, a long code line, a bleeding figure) are honest
// mistakes and warn; overflow on many pages is a systematic block enlargement
// and errors, as does a page whose text is mostly outside the block.
function checkTextBlock(doc, r) {
  const { x, y } = doc.window;
  // classify each page's overflow first, so the level can reflect how
  // widespread it is across the document
  const pages = [];
  for (const p of doc.pages) {
    const pl = solidLines(p);
    const wide = pl.filter((l) => l.x0 < x.lo - WINDOW_SLACK
                               || l.x1 > x.hi + WINDOW_SLACK);
    const tall = pl.filter((l) => l.y0 < y.lo - WINDOW_SLACK
                               || l.y1 > y.hi + WINDOW_SLACK);
    const culprits = wide.concat(tall.filter((l) => !wide.includes(l)));
    const out = culprits.length ? Math.max(...culprits.flatMap((l) =>
      [x.lo - l.x0, l.x1 - x.hi, y.lo - l.y0, l.y1 - y.hi])) : 0;
    const whole = culprits.length >= MIN_WHOLE
                  && culprits.length > pl.length * CULPRIT_SHARE;
    pages.push({ p, pl, wide, tall, culprits, out, whole });
  }
  // systematic: a page over-full end to end, or text spilling on many pages
  // AND on more than half the document (an enlarged block, not scattered
  // isolated overflows like a wide table or an unbreakable URL here and there)
  const overflowPages = pages.filter((i) => i.culprits.length).length;
  const systematic = pages.some((i) => i.whole)
    || (overflowPages > SYSTEMIC_PAGES
        && overflowPages > SYSTEMIC_FRAC * doc.pages.length);

  const findings = [];
  for (const i of pages) {
    if (i.culprits.length && i.whole) {
      const box = textBBox(i.p);
      findings.push(report("text-block-page",
        { page: i.p.number, w: box.x1 - box.x0, h: box.y1 - box.y0, r },
        { page: i.p.number, bbox: asList(box) }));
    } else if (i.culprits.length) {
      const box = i.culprits.reduce((b, l) => union(b, l), null);
      findings.push(report("text-block-lines",
        { page: i.p.number, n: i.culprits.length, text: i.culprits[0].text,
          out: i.out, wide: i.wide.length, tall: i.tall.length, systematic, r },
        { page: i.p.number, bbox: asList(box) }));
    } else {
      const box = contentBBox(i.p);
      if (!box) continue;
      const w = box.x1 - box.x0, h = box.y1 - box.y0;
      if (w > r.blockW + r.graphicsTol || h > r.blockH + r.graphicsTol) {
        findings.push(report("text-block-graphics",
          { page: i.p.number, w, h, r }, { page: i.p.number, bbox: asList(box) }));
      }
    }
  }
  return findings;
}

// Body text must be 10 pt Times (dominant size and font family).
function checkFont(doc, r) {
  const findings = [];
  if (doc.bodySize < r.fontWarn) {
    findings.push(report("font-size", { size: doc.bodySize, r }));
  }
  if (!TIMES_RE.test(doc.bodyFont)) {
    findings.push(report("font-family", { font: doc.bodyFont }));
  }
  return findings;
}

// Baselines must be 12 pt apart, checked per page so locally applied
// squeezing (e.g. savetrees' \linespread) cannot hide behind the average.
function checkLeading(doc, r) {
  const byPage = new Map();
  for (const [page, gap] of bodyGaps(doc)) {
    if (!byPage.has(page)) byPage.set(page, new Map());
    tally(byPage.get(page), gap);
  }
  const modes = new Map();
  for (const [page, counts] of byPage) {
    if (total(counts) >= MIN_GAPS) modes.set(page, mode(counts));
  }
  for (const limit of [r.leadingErr, r.leadingWarn]) {
    const bad = [...modes.keys()].filter((pg) => modes.get(pg) < limit)
      .sort((a, b) => a - b);
    if (bad.length) {
      return [report("leading", { pages: bad, sample: modes.get(bad[0]), r },
                     { page: bad[0], pages: bad })];
    }
  }
  return [];
}

// Most lines must lie entirely in one half of the page (heuristic).
function checkTwoColumn(doc, r) {
  const body = doc.pages.slice(0, r.bodyPages).flatMap((p) => p.lines);
  const mid = r.pageW / 2;
  const split = body.filter((l) => l.x1 < mid || l.x0 > mid).length;
  if (body.length && split / body.length < COLUMN_SHARE) {
    return [report("two-column")];
  }
  return [];
}

// Whitespace above section headings must not be compressed: the template
// leaves >= ~12.6 pt, titlesec/savetrees-style abuse ~6-8 pt.
function checkHeadingSpace(doc, r) {
  const squeezed = [];
  for (const p of doc.pages) {
    const left = p.lines.filter((l) => l.x1 < p.width / 2);
    const right = p.lines.filter((l) => l.x0 > p.width / 2);
    for (const col of [left, right]) {
      col.sort((a, b) => a.y0 - b.y0); // top to bottom
      for (let i = 1; i < col.length; i++) {
        const above = col[i - 1], line = col[i];
        const gap = line.y0 - above.y1;
        // a run-in \paragraph{} / description label is a bold body-size
        // lead-in whose paragraph text continues on the same baseline to its
        // right (its small gap above is the template's own); a true section
        // heading stands alone on its line. (nfonts === 1 catches the case
        // where the label and its text share one extracted line.)
        const runIn = p.lines.some((n) => n !== line
          && Math.abs(n.baseline - line.baseline) < 2
          && n.x0 >= line.x1 - 2 && n.x0 < line.x0 + p.width / 2);
        if (gap > 0 && gap < r.headingGap && line.nfonts === 1 && !runIn
            && SECTION_RE.test(line.text) && isHeading(doc, line)) {
          squeezed.push([p.number, line]);
        }
      }
    }
  }
  if (squeezed.length < MIN_SQUEEZED) return [];
  const pages = new Set(squeezed.map(([pno]) => pno));
  return [report("heading-space",
    { n: squeezed.length, pages: [...pages] },
    { page: Math.min(...pages), pages,
      boxes: squeezed.map(([pno, l]) => [pno, asList(l)]) })];
}

// Page-1 front matter, checked three ways. The title is the large centered
// lines up top; the abstract heading marks the top of the body.
//   title-space  -- the \maketitle whitespace below the title is not trimmed.
//   front-matter -- the body does not start too high (front matter reserves
//                   its space); an empty or anonymized author block is fine.
//   anonymity    -- IF the author block names people, it should look blinded.
function checkFrontMatter(doc, r) {
  const p1 = doc.pages[0];
  const title = p1.lines.filter((l) => l.size >= TITLE_MIN && l.size <= TITLE_MAX
                                    && l.y0 < p1.height / 2);
  if (!title.length) return [];
  const findings = [];
  const titleBottom = Math.max(...title.map((l) => l.y1));
  const below = p1.lines.filter((l) => solid(l) && l.y0 > titleBottom)
                        .sort((a, b) => a.y0 - b.y0)[0];
  const gap = below ? below.y0 - titleBottom : null;
  if (gap !== null && gap < r.titleGapWarn) {
    findings.push(report("title-space", { gap, r },
                         { page: 1, bbox: asList(below) }));
  }
  const abstract = p1.lines.find((l) => ABSTRACT_RE.test(l.text));
  if (abstract && abstract.y0 < r.bodyStartWarn) {
    findings.push(report("front-matter", { top: abstract.y0, r },
                         { page: 1, bbox: asList(abstract) }));
  }
  // the author block sits between the title and the abstract; we only check
  // it for anonymity when it actually names someone (an empty block, or the
  // unfilled template placeholder, is allowed)
  const block = abstract
    ? p1.lines.filter((l) => solid(l) && l.y0 > titleBottom
                          && l.y1 < abstract.y0)
    : [];
  const blinded = (l) => ANON_RE.test(l.text) || PLACEHOLDER_RE.test(l.text);
  if (block.length && !block.some(blinded)) {
    const affil = block.find((l) => AFFIL_RE.test(l.text));
    const shown = affil || block[0];
    findings.push(report("anonymity", { text: shown.text, affil: !!affil },
                         { page: 1, bbox: asList(shown) }));
  }
  return findings;
}

// The main body must fit in the page limit. The body ends where doc.bodyEnd
// (the first References or appendix heading) begins: the CFP places the
// mandatory appendices after the body and before References, and they do NOT
// count toward the limit. So the body fits iff that heading starts within
// the limit, or at the top of the very next page (the body then used exactly
// bodyPages full pages); a heading starting lower on that page means body
// text spilled past the limit.
function checkPageLimit(doc, r) {
  const end = doc.bodyEnd;
  if (!end) return [report("page-limit-unknown", { r })];
  const spilled = end.page > r.bodyPages + 1
    || (end.page === r.bodyPages + 1 && end.y0 > doc.window.y.lo + LIMIT_TOP_SLACK);
  return spilled
    ? [report("page-limit-exceeded", { text: end.text, page: end.page, r },
              { page: end.page, bbox: asList(end) })]
    : [];
}

// The CFP appendices must be present (required -> error, else warning).
function checkRequiredSections(doc, r) {
  const findings = [];
  for (const [rule, title, pattern, required] of r.sections) {
    if (!findHeading(doc, pattern)) {
      findings.push(report("section-missing", { rule, title, required }));
    }
  }
  return findings;
}

// Submissions are anonymized: no author name in the PDF metadata.
function checkMetadata(doc, r) {
  const author = (doc.author || "").trim();
  if (!author) return [];
  return [report("metadata", { author })];
}

const CHECKS = [checkPageSize, checkTextBlock, checkFont, checkLeading,
                checkTwoColumn, checkHeadingSpace, checkFrontMatter,
                checkPageLimit, checkRequiredSections, checkMetadata];

// --- entry points -------------------------------------------------------------
// -----------------------------------------------------------------------------

// Open PDF bytes (ArrayBuffer or Uint8Array) as a MuPDF document.
// The caller owns it: call .destroy() when done, or keep it for rendering.
export function openDocument(data) {
  return mupdf.Document.openDocument(data, "application/pdf");
}

// Check an already-opened document; returns a JSON-able result.
export function checkDocument(mupdfDoc, rules = RULES) {
  let doc;
  try {
    if (mupdfDoc.needsPassword()) throw new Error("the file is password-protected");
    doc = analyze(mupdfDoc, rules);
  } catch (exc) {
    return { version: VERSION, ok: false, stats: {},
             findings: [report("parse", { verb: "analyze",
                                          error: exc.message })] };
  }
  const findings = CHECKS.flatMap((check) => check(doc, rules));
  findings.sort((a, b) => (a.level !== "error") - (b.level !== "error"));
  const refs = findHeading(doc, REFS_RE);
  const leading = new Map();
  for (const [, gap] of bodyGaps(doc)) tally(leading, gap);
  // where the References and each present appendix begin, in page order
  const landmarks = [refs, ...rules.sections.map(([, , p]) => findHeading(doc, p))]
    .filter(Boolean)
    .map((h) => ({ text: h.text.slice(0, 30), page: h.page, y: h.y0 }))
    .sort((a, b) => a.page - b.page || a.y - b.y);
  return {
    version: VERSION,
    ok: findings.length === 0,  // strict: any error or warning clears it
    findings,
    stats: {
      pages: doc.pages.length,
      body_font_pt: doc.bodySize,
      body_font_name: doc.bodyFont,
      leading_pt: leading.size ? mode(leading) : null,
      refs_page: refs ? refs.page : null,
      landmarks,                              // References + appendices, by page
      body_pages_limit: rules.bodyPages,      // ui: "body limit" page caption
      block_window: [doc.window.x.lo, doc.window.y.lo,   // ui: green overlay
                     doc.window.x.hi, doc.window.y.hi],
      page_boxes: doc.pages.map((p) => asList(contentBBox(p))), // ui: blue
    },
  };
}

// Convenience one-shot: open, check, clean up.
export function checkPdf(data, rules = RULES) {
  let doc = null;
  try {
    doc = openDocument(data);
  } catch (exc) {
    return { version: VERSION, ok: false, stats: {},
             findings: [report("parse", { verb: "open",
                                          error: exc.message })] };
  }
  try {
    return checkDocument(doc, rules);
  } finally {
    doc.destroy();
  }
}

// Human-readable report, shared by the CLI and the web page's copy button.
export function formatReport(name, result) {
  const out = [`== ${name} (checker v${result.version})`];
  const s = result.stats;
  if (s.pages) {
    const marks = s.landmarks.length
      ? s.landmarks.map((m) => `${m.text} p.${m.page}`).join(", ")
      : "no References/appendix heading found";
    out.push(`   ${s.pages} pages | body font ${num(s.body_font_pt)} pt ` +
             `(${s.body_font_name}) | leading ` +
             `${s.leading_pt === null ? "?" : num(s.leading_pt)} pt`);
    out.push(`   end matter: ${marks}`);
  }
  for (const f of result.findings) {
    out.push(`   ${f.level.toUpperCase().padEnd(7)} [${f.rule}] ${f.message}`);
  }
  const errors = result.findings.filter((f) => f.level === "error").length;
  const warnings = result.findings.length - errors;
  const verdict = errors ? "ERROR" : warnings ? "WARNING" : "PASS";
  out.push(`   ${verdict}: ${errors} error(s), ${warnings} warning(s)`);
  return out.join("\n");
}
