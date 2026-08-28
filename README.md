# Italian payslip PDF redactor

This small command-line tool processes every PDF in a folder and creates a
redacted copy in another folder. It runs the
[OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) locally to
find personal names, addresses, account numbers, email addresses, phone numbers,
dates, URLs, and secrets.

It also adds payslip-specific protection:

- Italian tax codes and IBANs are detected with patterns.
- Lines mentioning a bank, IBAN, SWIFT/BIC, or salary credit are fully removed.
- The top 18% of every page is removed by default, because employer names and
  addresses are commonly in the header and the model has no company-name label.
- Known company or bank names can be supplied explicitly with `--redact-term`.

Redactions are applied to the PDF content, not merely drawn over it. The original
files are never modified. Embedded standard metadata and XML/XMP metadata are
removed from every output PDF before it is saved.

## Requirements

- Python 3.10 or newer
- Enough disk space and memory for the model (the first run downloads roughly a
  1B-parameter model)
- Searchable-text PDFs. Scanned/image-only files require OCR first.

The model runs locally after download. The payslip contents are not sent to an
OpenAI API.

## Install

From this directory, create a virtual environment and install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run

Put the original PDFs in a folder such as `input_pdfs`, then run:

```bash
python redact_payslips.py input_pdfs redacted_pdfs
```

The outputs receive neutral sequential names such as `payslip_0001.pdf`, so an
employee identifier in an original filename is not copied. Choose another neutral
prefix with `--filename-prefix sanitized`.

For a known employer and bank, improve coverage by naming them explicitly:

```bash
python redact_payslips.py input_pdfs redacted_pdfs \
  --redact-term "Azienda Esempio S.r.l." \
  --redact-term "Banca Esempio"
```

The default device is CPU. A CUDA-enabled machine can use:

```bash
python redact_payslips.py input_pdfs redacted_pdfs --device cuda:0
```

If the employer block is taller or shorter, adjust the redacted top portion:

```bash
python redact_payslips.py input_pdfs redacted_pdfs --header-fraction 0.25
```

Use `--header-fraction 0` only if employer details are covered by explicit terms
or another rule.

The pay period (for example, `Gennaio 2017`) and the value next to `NETTO DEL
MESE` are preserved automatically. To prevent a false positive from being
redacted, preserve exact text or a pattern:

```bash
python redact_payslips.py input_pdfs redacted_pdfs \
  --keep-term "Gennaio 2017" \
  --keep-regex 'EUR\s+1[.]234,56'
```

Keep rules override model and employer-header detections, but cannot preserve an
Italian tax code, IBAN, bank-information line, or text explicitly supplied with
`--redact-term`. Regexes use Python syntax and are case-insensitive. If an entire
model category is unwanted, it can be disabled:

```bash
python redact_payslips.py input_pdfs redacted_pdfs --keep-category private_date
```

Category-level exceptions are broad: the example also keeps birth and employment
dates. Prefer `--keep-term` or `--keep-regex` whenever possible.

## Important review step

Manually inspect every output before sharing it. Privacy Filter is primarily
trained for English and its own documentation warns that it can miss data,
especially in non-English and high-sensitivity financial/HR documents. PDF text
extraction can also split fields unexpectedly. A warning about pages with no
searchable text means those pages were not processed and must be OCRed first.

Keep source and redacted folders separate, and do not overwrite originals.
