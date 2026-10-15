#!/usr/bin/env bash
set -u

project_dir="${1:-.}"
missing=0

for required_file in polymorphic.p4 mycontroller.py Makefile; do
    if [[ -f "$project_dir/$required_file" ]]; then
        echo "OK file=$required_file"
    else
        echo "MISSING file=$required_file"
        missing=1
    fi
done

if [[ -f "$project_dir/README.md" ]]; then
    echo "OK file=README.md"
else
    echo "MISSING file=README.md"
    missing=1
fi

for required_dir in topo utils; do
    if [[ -d "$project_dir/$required_dir" ]]; then
        echo "OK directory=$required_dir"
    else
        echo "MISSING directory=$required_dir"
        missing=1
    fi
done

if [[ "$missing" -ne 0 ]]; then
    echo "SUBMISSION_CHECK failed"
    exit 1
fi

echo "SUBMISSION_CHECK passed"
