# Vendored MuPDF.js

Unmodified `dist/` files from the official [`mupdf` npm package](https://www.npmjs.com/package/mupdf)
version 1.28.0 (see `package.json`), published by [Artifex](https://mupdf.com), license AGPL-3.0-or-later
(see `LICENSE`). Vendored so that the checker runs with no build step and no
package manager, and so the exact WASM binary every author and chair runs is
pinned in version control.

To upgrade: `npm pack mupdf` and extract/replace these files.
