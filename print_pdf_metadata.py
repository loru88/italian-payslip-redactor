#!/usr/bin/env python3
"""Print embedded metadata from a PDF file or every PDF in a folder."""

from __future__ import annotations

import argparse
from pathlib import Path

import pymupdf


def pdf_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix.lower() == ".pdf":
        return [path]
    if path.is_dir():
        return sorted(
            item for item in path.iterdir() if item.is_file() and item.suffix.lower() == ".pdf"
        )
    return []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print embedded metadata from a PDF file or folder of PDFs."
    )
    parser.add_argument("path", type=Path, help="PDF file or folder containing PDFs")
    args = parser.parse_args()

    files = pdf_files(args.path)
    if not files:
        parser.error(f"no PDF files found at: {args.path}")

    for index, filename in enumerate(files):
        if index:
            print()
        print(f"PDF: {filename}")
        try:
            with pymupdf.open(filename) as document:
                metadata = document.metadata or {}
                for key, value in metadata.items():
                    print(f"{key}: {value or ''}")
        except Exception as exc:
            print(f"ERROR: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
