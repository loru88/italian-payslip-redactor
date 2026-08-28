#!/usr/bin/env python3
"""Permanently redact sensitive text from a directory of Italian payslip PDFs."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pymupdf as fitz
from transformers import pipeline


MODEL_NAME = "openai/privacy-filter"
SENSITIVE_LABELS = {
    "account_number",
    "private_address",
    "private_email",
    "private_person",
    "private_phone",
    "private_url",
    "private_date",
    "secret",
}
BANK_RE = re.compile(
    r"\b(?:IBAN|BANCA|BANCO|ISTITUTO\s+DI\s+CREDITO|ACCREDITO|COORDINATE\s+BANCARIE|BIC|SWIFT)\b",
    re.IGNORECASE,
)
ITALIAN_ID_RE = re.compile(
    r"\b(?:[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]|IT\d{2}[A-Z]\d{10}[A-Z0-9]{12})\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TextWord:
    start: int
    end: int
    rect: fitz.Rect
    line_key: tuple[int, int]


def page_text_map(page: fitz.Page) -> tuple[str, list[TextWord], dict[tuple[int, int], list[fitz.Rect]]]:
    """Build model input while retaining character-to-PDF-coordinate mappings."""
    raw_words = page.get_text("words", sort=True)
    parts: list[str] = []
    mapped: list[TextWord] = []
    lines: dict[tuple[int, int], list[fitz.Rect]] = {}
    previous_line: tuple[int, int] | None = None
    offset = 0

    for x0, y0, x1, y1, word, block, line, _word_no in raw_words:
        key = (int(block), int(line))
        separator = "\n" if previous_line is not None and key != previous_line else (" " if parts else "")
        parts.append(separator)
        offset += len(separator)
        start = offset
        parts.append(str(word))
        end = start + len(str(word))
        offset = end
        rect = fitz.Rect(x0, y0, x1, y1)
        mapped.append(TextWord(start, end, rect, key))
        lines.setdefault(key, []).append(rect)
        previous_line = key

    return "".join(parts), mapped, lines


def overlaps(word: TextWord, spans: Iterable[tuple[int, int]]) -> bool:
    return any(word.start < end and word.end > start for start, end in spans)


def label_name(item: dict) -> str:
    label = str(item.get("entity_group", item.get("entity", ""))).lower()
    return re.sub(r"^[bies]-", "", label)


def value_field_words(words: list[TextWord], text: str, pattern: re.Pattern[str]) -> set[int]:
    """Protect a labelled field and its nearby value, even when they are separate PDF lines."""
    matching = [word for word in words if pattern.search(text[word.start : word.end])]
    if not matching:
        # Labels such as "N E T T O" are split into individual PDF words.
        for key in {word.line_key for word in words}:
            indexes = [i for i, word in enumerate(words) if word.line_key == key]
            compact = re.sub(r"\s+", "", " ".join(text[words[i].start : words[i].end] for i in indexes))
            if pattern.search(compact):
                matching.extend(words[i] for i in indexes)
    if not matching:
        return set()

    area = matching[0].rect
    for word in matching[1:]:
        area |= word.rect
    value_area = fitz.Rect(area.x0 - 25, area.y0 - 3, area.x1 + 70, area.y1 + 22)
    return {i for i, word in enumerate(words) if word.rect.intersects(value_area)}


def merge_rectangles(rectangles: Iterable[fitz.Rect]) -> list[fitz.Rect]:
    """Join adjacent word rectangles on the same visual line."""
    rects = sorted(rectangles, key=lambda r: (round(r.y0, 1), r.x0))
    merged: list[fitz.Rect] = []
    for rect in rects:
        padded = fitz.Rect(rect.x0 - 1, rect.y0 - 1, rect.x1 + 1, rect.y1 + 1)
        if merged and abs(merged[-1].y0 - padded.y0) < 2 and padded.x0 - merged[-1].x1 < 5:
            merged[-1] |= padded
        else:
            merged.append(padded)
    return merged


def clear_pdf_metadata(document: fitz.Document) -> None:
    """Remove standard Info-dictionary and XML/XMP metadata from the output."""
    document.set_metadata({})
    document.del_xml_metadata()


def redact_pdf(
    source: Path,
    destination: Path,
    classifier,
    header_fraction: float,
    exact_terms: list[str],
    keep_terms: list[str],
    keep_patterns: list[re.Pattern[str]],
    keep_categories: set[str],
) -> tuple[int, int]:
    document = fitz.open(source)
    total_marks = 0
    pages_without_text = 0

    for page in document:
        text, words, lines = page_text_map(page)
        if not text.strip():
            pages_without_text += 1
            continue

        predictions = classifier(text, aggregation_strategy="simple")
        model_spans = [
            (int(item["start"]), int(item["end"]))
            for item in predictions
            if label_name(item) in SENSITIVE_LABELS and label_name(item) not in keep_categories
        ]
        mandatory_spans = [(match.start(), match.end()) for match in ITALIAN_ID_RE.finditer(text)]
        forced_spans: list[tuple[int, int]] = []
        lowered = text.casefold()
        for term in exact_terms:
            needle = term.casefold().strip()
            if needle:
                start = 0
                while (found := lowered.find(needle, start)) >= 0:
                    forced_spans.append((found, found + len(needle)))
                    start = found + len(needle)

        keep_spans: list[tuple[int, int]] = []
        for term in keep_terms:
            needle = term.casefold().strip()
            if needle:
                start = 0
                while (found := lowered.find(needle, start)) >= 0:
                    keep_spans.append((found, found + len(needle)))
                    start = found + len(needle)
        for pattern in keep_patterns:
            keep_spans.extend((match.start(), match.end()) for match in pattern.finditer(text))

        protected_indexes = {
            i for i, word in enumerate(words) if overlaps(word, keep_spans)
        }
        protected_indexes |= value_field_words(words, text, re.compile(r"PERIODO|RETRIBUZIONE", re.I))
        protected_indexes |= value_field_words(words, text, re.compile(r"NETTO(?:DEL)?MESE", re.I))

        rectangles = [
            word.rect
            for i, word in enumerate(words)
            if overlaps(word, model_spans) and i not in protected_indexes
        ]
        # Explicit redactions, tax codes, and IBANs always win over keep rules.
        rectangles.extend(
            word.rect for word in words if overlaps(word, [*forced_spans, *mandatory_spans])
        )

        # Employer name/address is normally in the top section. Redacting the whole
        # band avoids pretending the model can identify organisations (it cannot).
        if header_fraction > 0:
            header_limit = page.rect.height * header_fraction
            rectangles.extend(
                word.rect
                for i, word in enumerate(words)
                if word.rect.y0 < header_limit and i not in protected_indexes
            )
            header = fitz.Rect(page.rect.x0, page.rect.y0, page.rect.x1, header_limit)
            for image in page.get_images(full=True):
                for image_rect in page.get_image_rects(image[0]):
                    if image_rect.intersects(header):
                        rectangles.append(image_rect)

        # Bank labels and values usually share a line; remove the complete line.
        for key, line_rects in lines.items():
            line_words = [w for w in words if w.line_key == key]
            line_text = " ".join(text[w.start : w.end] for w in line_words)
            if BANK_RE.search(line_text):
                rectangles.extend(line_rects)

        marks = merge_rectangles(rectangles)
        for rect in marks:
            page.add_redact_annot(rect, fill=(0, 0, 0))
        if marks:
            page.apply_redactions()
            total_marks += len(marks)

    clear_pdf_metadata(document)
    destination.parent.mkdir(parents=True, exist_ok=True)
    document.save(destination, garbage=4, deflate=True, clean=True)
    document.close()
    return total_marks, pages_without_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path, help="Folder containing PDF files")
    parser.add_argument("output_dir", type=Path, help="Folder for redacted PDF files")
    parser.add_argument("--device", default="cpu", help="Transformers device, e.g. cpu, cuda, cuda:0, mps")
    parser.add_argument(
        "--header-fraction",
        type=float,
        default=0.18,
        help="Fraction of each page redacted from the top for employer details (default: 0.18)",
    )
    parser.add_argument(
        "--redact-term",
        action="append",
        default=[],
        help="Exact company/bank text to redact everywhere; may be repeated",
    )
    parser.add_argument(
        "--keep-term",
        action="append",
        default=[],
        help="Exact non-sensitive text that model/header rules must preserve; may be repeated",
    )
    parser.add_argument(
        "--keep-regex",
        action="append",
        default=[],
        help="Python regex for non-sensitive text to preserve; may be repeated",
    )
    parser.add_argument(
        "--keep-category",
        action="append",
        choices=sorted(SENSITIVE_LABELS),
        default=[],
        help="Disable a Privacy Filter category globally (use cautiously)",
    )
    parser.add_argument(
        "--filename-prefix",
        default="payslip",
        help="Neutral output filename prefix (default: payslip)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input_dir.is_dir():
        print(f"Input directory does not exist: {args.input_dir}", file=sys.stderr)
        return 2
    if not 0 <= args.header_fraction <= 1:
        print("--header-fraction must be between 0 and 1", file=sys.stderr)
        return 2
    try:
        keep_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in args.keep_regex]
    except re.error as exc:
        print(f"Invalid --keep-regex: {exc}", file=sys.stderr)
        return 2
    if not args.filename_prefix or Path(args.filename_prefix).name != args.filename_prefix:
        print("--filename-prefix must be a plain filename component", file=sys.stderr)
        return 2

    pdfs = sorted(path for path in args.input_dir.iterdir() if path.is_file() and path.suffix.lower() == ".pdf")
    if not pdfs:
        print(f"No PDF files found in {args.input_dir}", file=sys.stderr)
        return 1

    print(f"Loading {MODEL_NAME} on {args.device} ...")
    classifier = pipeline("token-classification", model=MODEL_NAME, device=args.device)

    failures = 0
    for index, source in enumerate(pdfs, start=1):
        destination = args.output_dir / f"{args.filename_prefix}_{index:04d}.pdf"
        if destination.resolve() == source.resolve():
            print(f"ERROR {source.name}: input and output paths are identical", file=sys.stderr)
            failures += 1
            continue
        try:
            marks, image_pages = redact_pdf(
                source,
                destination,
                classifier,
                args.header_fraction,
                args.redact_term,
                args.keep_term,
                keep_patterns,
                set(args.keep_category),
            )
            warning = f"; WARNING: {image_pages} page(s) had no searchable text" if image_pages else ""
            print(f"OK {source.name} -> {destination.name}: {marks} redaction area(s){warning}")
        except Exception as exc:  # continue processing the remaining batch
            print(f"ERROR {source.name}: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
