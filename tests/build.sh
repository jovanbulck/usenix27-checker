#!/usr/bin/env bash
# Compile every tests/sources/*.tex into tests/pdfs/<name>.pdf.
#
# Requires pdflatex + latexmk (TeX Live) with the packages listed in
# tests/README.md. The official usenix.sty lives in tests/template/ and is
# put on TEXINPUTS, so the sources compile exactly like an author's paper.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p pdfs build
export TEXINPUTS="./template:"
export SOURCE_DATE_EPOCH=0   # reproducible PDFs
for src in sources/*.tex; do
  name=$(basename "$src" .tex)
  echo "== $name"
  latexmk -pdf -interaction=nonstopmode -halt-on-error \
          -output-directory=build "$src" > "build/$name.log.txt" 2>&1 \
    || { echo "BUILD FAILED; last lines of log:"; tail -30 "build/$name.log.txt"; exit 1; }
  cp "build/$name.pdf" pdfs/
done
echo "OK: $(ls pdfs/*.pdf | wc -l) PDFs in tests/pdfs/"
