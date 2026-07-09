// Browser front end: talks to the checker running in worker.js, renders the
// verdict, the findings list, and per-page thumbnails with overlays. All
// geometry from the checker is in PDF points with a top-left origin, so
// drawing on a canvas is a plain multiplication by the render scale.

import { VERSION } from "./version.js";

const $ = (id) => document.getElementById(id);

const THUMB_SCALE = 0.36; // page thumbnails
const ZOOM_SCALE = 2.0;   // full-page zoom view
const COLORS = { window: "#2E7D43", content: "#2B5C8A", problem: "#B3261E" };

// --- worker plumbing: one request, one matching reply, by id -----------------
// One worker (one WASM engine) PER DOCUMENT: a fresh check never inherits
// heap growth or engine state from the previous one, and terminating the
// old worker cancels its in-flight render requests (their promises reject
// as "superseded" so stale thumbnail loops stop cleanly).

let worker = null;
let workerUsed = false; // the initial idle worker may serve the first check
let pending = new Map();
let nextId = 1;

// (Re)start the engine; resolves with the checker version once loaded.
function startWorker() {
  if (worker) {
    worker.terminate();
    for (const request of pending.values()) {
      request.reject(new Error("superseded"));
    }
    pending = new Map();
  }
  workerUsed = false;
  worker = new Worker(`worker.js?v=${VERSION}`, { type: "module" });
  return new Promise((resolve, reject) => {
    worker.onmessage = (event) => {
      const msg = event.data;
      if (msg.type === "ready") { resolve(msg.version); return; }
      const request = pending.get(msg.id);
      if (!request) return;
      pending.delete(msg.id);
      if (msg.type === "error") request.reject(new Error(msg.message));
      else request.resolve(msg);
    };
    worker.onerror = (event) =>
      reject(new Error(event.message || "unknown error"));
  });
}

function ask(message, transfer = []) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ ...message, id }, transfer);
  });
}

$("status").textContent = "loading the checker (~4 MB, cached after the first visit)…";
startWorker().then(
  (version) => {
    $("status").textContent = `checker v${version} ready, waiting for a PDF`;
  },
  (exc) => {
    $("status").textContent = `checker failed to load (${exc.message}); ` +
      "check your network connection, or report this to the chairs";
  });

// --- checking a file ----------------------------------------------------------

let result = null;   // latest check result
let fileName = "";
let report = "";     // plain-text report for the copy button

$("file").onchange = () => check($("file").files[0]);
$("drop").ondragover = (e) => { e.preventDefault(); $("drop").classList.add("over"); };
$("drop").ondragleave = () => $("drop").classList.remove("over");
$("drop").ondrop = (e) => {
  e.preventDefault();
  $("drop").classList.remove("over");
  check(e.dataTransfer.files[0]);
};

async function check(file) {
  if (!file) return;
  fileName = file.name;
  for (const id of ["findings", "pages"]) $(id).innerHTML = "";
  $("pages").classList.remove("hideok");
  $("hideok").checked = false;
  $("verdict").style.display = "none";
  $("toolbar").style.display = "none";
  $("hint").hidden = true;
  $("status").textContent = `analyzing ${file.name}…`;
  try {
    const data = await file.arrayBuffer();
    if (workerUsed) await startWorker(); // fresh engine per document
    workerUsed = true;
    const reply = await ask({ type: "check", data });
    result = reply.result;
    $("status").textContent = "";
    show(result);
  } catch (exc) {
    if (exc.message === "superseded") return; // a newer file took over
    $("status").textContent = `could not analyze this PDF: ${exc.message}`;
  }
}

// --- presenting the result ----------------------------------------------------

// Worst finding level on page p: "error" > "warning" > "ok".
function pageLevel(p) {
  const levels = result.findings
    .filter((f) => f.page === p || (f.pages || []).includes(p))
    .map((f) => f.level);
  return levels.includes("error") ? "error"
    : levels.includes("warning") ? "warning" : "ok";
}

function show(r) {
  const errors = r.findings.filter((f) => f.level === "error").length;
  const warnings = r.findings.length - errors;
  const endMatter = (r.stats.landmarks || []).length
    ? r.stats.landmarks.map((m) => `${m.text} p.${m.page}`).join(", ")
    : "none found";
  const stats = `${errors} error(s), ${warnings} warning(s)` +
    (r.stats.pages ? ` · ${r.stats.pages} pages · body font ${r.stats.body_font_pt} pt` +
      ` · leading ${r.stats.leading_pt} pt · end matter: ${endMatter}` : "") +
    ` · checker v${r.version}`;
  const level = errors ? "fail" : warnings ? "warn" : "pass";
  $("verdict").style.display = "flex";
  $("verdict").className = level;
  $("vbadge").textContent = { fail: "✗", warn: "!", pass: "✓" }[level];
  $("vtitle").textContent = errors
    ? `${errors} error(s) found, please investigate below`
    : warnings
      ? `${warnings} warning(s) found, please check them below`
      : "No formatting issues found";
  $("stats").textContent = stats;
  $("hint").hidden = r.findings.length === 0;

  const messages = r.findings.map((f) => `${f.level.toUpperCase()} [${f.rule}] ${f.message}`);
  report = [`USENIX Security '27 format checker v${r.version}: ${fileName}`,
            `${errors ? "ERROR" : warnings ? "WARNING" : "PASS"}: ${stats}`,
            ...messages].join("\n");

  for (const [i, f] of r.findings.entries()) {
    const item = document.createElement("li");
    item.className = f.level;
    const tag = document.createElement("span");
    tag.className = "rule";
    tag.textContent = f.rule;
    item.append(tag, messages[i].replace(`${f.level.toUpperCase()} [${f.rule}] `, ""));
    $("findings").appendChild(item);
  }
  if (r.stats.page_boxes) renderAllPages();
}

// Ask the worker for one page as a PNG and draw it plus the overlays:
// the allowed text-block window (green), this page's measured content (blue),
// and any findings located on it (red).
async function renderPage(p, scale) {
  const reply = await ask({ type: "render", page: p, scale });
  const bitmap = await createImageBitmap(new Blob([reply.png], { type: "image/png" }));
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();

  const rect = ([x0, y0, x1, y1], color, dash) => {
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.setLineDash(dash || []);
    ctx.strokeRect(x0 * scale, y0 * scale, (x1 - x0) * scale, (y1 - y0) * scale);
  };
  rect(result.stats.block_window, COLORS.window, [4, 3]);
  if (result.stats.page_boxes[p - 1]) rect(result.stats.page_boxes[p - 1], COLORS.content);
  for (const f of result.findings) {
    if (f.page === p && f.bbox) rect(f.bbox, COLORS.problem);
    for (const [pg, b] of f.boxes || []) {
      if (pg === p) rect(b, COLORS.problem);
    }
  }
  return canvas;
}

async function renderAllPages() {
  $("toolbar").style.display = "flex";
  const marks = { ok: "✓", warning: "!", error: "✗" };
  const r = result; // a newer check supersedes this loop
  for (let p = 1; p <= r.stats.pages; p++) {
    const level = pageLevel(p);
    const figure = document.createElement("figure");
    figure.className = level === "ok" ? "ok" : "";
    let canvas;
    try {
      canvas = await renderPage(p, THUMB_SCALE);
    } catch (exc) {
      if (exc.message === "superseded") return;
      throw exc;
    }
    if (result !== r) return;
    canvas.onclick = () => openZoom(p);
    figure.appendChild(canvas);
    figure.insertAdjacentHTML("beforeend",
      `<span class="mark ${level}">${marks[level]}</span>`);
    const caption = document.createElement("figcaption");
    caption.textContent = `p.${p}` +
      (p === result.stats.body_pages_limit ? " · body limit" : "");
    figure.appendChild(caption);
    $("pages").appendChild(figure);
  }
}

// --- zoom overlay: click a page, flip through with arrow keys ------------------

let zoomPage = null;

async function openZoom(p) {
  zoomPage = p;
  let canvas;
  try {
    canvas = await renderPage(p, ZOOM_SCALE);
  } catch (exc) {
    if (exc.message === "superseded") return;
    throw exc;
  }
  if (zoomPage !== p) return; // a newer page was requested while rendering
  $("zoom").replaceChildren(canvas);
  $("zoom").insertAdjacentHTML("beforeend",
    `<div class="hint">page ${p} of ${result.stats.pages} · ` +
    "← → to flip through, click or Esc to close</div>");
  const wasOpen = $("zoom").style.display === "block";
  $("zoom").style.display = "block";
  if (wasOpen) $("zoom").scrollTop = 0;
}

$("zoom").onclick = () => {
  zoomPage = null;
  $("zoom").style.display = "none";
  $("zoom").replaceChildren();
};

addEventListener("keydown", (e) => {
  if (e.key === "Escape") $("zoom").onclick();
  if (zoomPage === null) return;
  if (e.key === "ArrowRight" && zoomPage < result.stats.pages) {
    e.preventDefault();
    openZoom(zoomPage + 1);
  }
  if (e.key === "ArrowLeft" && zoomPage > 1) {
    e.preventDefault();
    openZoom(zoomPage - 1);
  }
});

// --- toolbar ------------------------------------------------------------------

$("copy").onclick = async () => {
  await navigator.clipboard.writeText(report);
  $("copy").classList.add("done");
  $("copy-label").textContent = "Copied";
  setTimeout(() => {
    $("copy").classList.remove("done");
    $("copy-label").textContent = "Copy report";
  }, 1500);
};

$("hideok").onchange = () =>
  $("pages").classList.toggle("hideok", $("hideok").checked);
