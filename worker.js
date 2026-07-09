// Web Worker: owns the MuPDF engine and the currently checked document.
// A malformed PDF can at worst crash this worker, never the page. The main
// thread (ui.js) sends {id, type: "check"|"render"} requests and receives
// {id, ...} replies; "ready" is announced once the WASM engine has loaded.
//
// The engine is imported dynamically so that the message handler exists from
// the very first moment: messages that arrive while the WASM is still loading
// simply wait for it instead of being dropped.
//
// The ?v=<version> query this worker was loaded with is forwarded to the
// checker import, so a version bump busts stale caches (Firefox keeps worker
// modules cached across hard reloads).
const engine = Promise.all([import("./vendor/mupdf/mupdf.js"),
                            import(`./checker.js${self.location.search}`)]);
engine.then(([, checker]) => postMessage({ type: "ready",
                                           version: checker.VERSION }),
            (exc) => postMessage({ type: "error", id: 0,
                                   message: String(exc && exc.message || exc) }));

let doc = null; // the last checked document, kept for render requests

onmessage = async (event) => {
  const msg = event.data;
  try {
    const [mupdf, checker] = await engine;
    if (msg.type === "check") {
      if (doc) doc.destroy();
      doc = checker.openDocument(msg.data);
      postMessage({ id: msg.id, type: "result",
                    result: checker.checkDocument(doc) });
    } else if (msg.type === "render") {
      const page = doc.loadPage(msg.page - 1);
      const pixmap = page.toPixmap(mupdf.Matrix.scale(msg.scale, msg.scale),
                                   mupdf.ColorSpace.DeviceRGB, false);
      const png = pixmap.asPNG();
      pixmap.destroy();
      page.destroy();
      postMessage({ id: msg.id, type: "page", png }, [png.buffer]);
    }
  } catch (exc) {
    postMessage({ id: msg.id, type: "error",
                  message: String(exc && exc.message || exc) });
  }
};
