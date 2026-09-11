# PrivacyGuard

Text-based PII redaction for TXT, PDF, DOCX, and PPTX files.

## Run

```bash
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5001`.

## What It Does

- Extracts text from uploaded TXT, PDF, DOCX, and PPTX files.
- Scans extracted text with regex patterns for common PII:
  - Social Security numbers
  - Driver license numbers
  - State ID numbers
  - Passport numbers
  - Credit card numbers, expiration dates, and security codes
  - Bank routing and account numbers
  - Emails, phone numbers, addresses, dates of birth, usernames, passwords, API keys, and IP addresses
- Lets the user choose which findings to redact.
- Generates a redacted copy in the same file format as the upload.
- Preserves PDF page layout by applying black redaction boxes over selected text in the original PDF.
- Masks selected text in DOCX and PPTX files in-place so the original document structure is kept as much as possible.
- Keeps uploaded and redacted files only for the current browser session.
