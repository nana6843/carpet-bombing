#!/usr/bin/env bash
#
# Restore the large CSVs that ship gzipped in this repository.
# Run once after cloning; the .csv.gz files are kept.
#
set -euo pipefail
cd "$(dirname "$0")"
find . -name '*.csv.gz' -print0 | xargs -0 -P 4 -I{} gzip -dkf {}
echo "unpacked $(find . -name '*.csv.gz' | wc -l) CSV files"
