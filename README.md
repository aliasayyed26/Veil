# Veil — Privacy-First Client-Side PII Sanitizer

Veil is a 100% client-side web application that detects, classifies, highlights, and redacts Personally Identifiable Information (PII) in pasted text, `.txt` files, and `.csv` files directly inside the browser. Zero original data ever leaves the page.

## Features & Privacy Guarantees

- **Zero Backend & Zero Network Calls**: No API requests, no external AI, no analytics, no CDNs, and no web fonts (uses the native system font stack).
- **Zero Persistence**: No `localStorage`, `sessionStorage`, `IndexedDB`, or cookies are used for document content; no document content is logged to the console.
- **Safe DOM Rendering**: User text and highlighted tokens are rendered strictly via `document.createTextNode` and `textContent` (no `innerHTML` with user data).
- **Three Live-Switchable Redaction Modes**:
  1. **Full Mask**: Replaces every detected entity with `[REDACTED]`.
  2. **Partial Mask**: Preserves minimal non-sensitive shape/suffix (e.g., `r***@g***.com`, `XXXXXX1234`, `XXXXX1234X`, `XXXX-XXXX-XXXX-1234`, `XXX.XXX.XXX.XXX`, `XXXX XXXX 1234`).
  3. **Consistent Pseudonymize**: Assigns per-type placeholders (`USER_01`, `PHONE_01`, `IP_01`, `PAN_01`, `AADHAAR_01`, `CARD_01`) using normalized values in memory only, rebuilt fresh on every run and never displayed or exported.
- **Sanitized-Only Exports**: Download sanitized `.txt` or `.csv` (`.csv` enabled only for CSV uploads) via the Blob API with immediate Object URL revocation, or copy sanitized output via the Clipboard API.

---

## Project Structure

```text
/
├── index.html                 # Main Veil dashboard UI
├── sample-test-data.txt       # Synthetic sample data file for .txt upload testing
├── README.md                  # Documentation, architecture, limitations & pitch
├── src/
│   ├── styles.css             # Mocha brown, platinum silver & pale lavender UI with live animations (system fonts, reduced-motion, focus styles)
│   ├── main.js                # UI state, debounced live processing, safe DOM rendering, events
│   ├── detectors.js           # Regex detectors, Luhn & Verhoeff validators, overlap classification
│   ├── redact.js              # Full, Partial, and in-memory Pseudonymization engines
│   ├── audit.js               # Privacy-safe session audit summary (counts & metadata only)
│   ├── export.js              # File validation, sanitized Blob download, Clipboard copy
│   └── sample.js              # Synthetic sample payload & static build Prompt Log
└── tests/
    ├── tests.js               # Shared acceptance test suite (runnable in Node & browser)
    └── detectors.test.html    # In-browser acceptance test runner
```

---

## Setup & Run Instructions

Veil has **zero runtime or build dependencies**. You can run it in either of two ways:

### Option 1: Open Directly
Open `index.html` directly in any modern browser (`File -> Open File` or double-click `index.html`).

### Option 2: Run a Local Static Server
From the project root directory, start any static HTTP server:

```bash
# Using Node.js (zero-config)
npx --yes serve .

# Or using Python 3
python -m http.server 8080
```

Then open `http://localhost:3000` (for `serve`) or `http://localhost:8080` (for Python).

### Running the Acceptance Tests
- **CLI (Node.js)**:
  ```bash
  node tests/tests.js
  ```
- **In-Browser**:
  Open `tests/detectors.test.html` in your browser (directly or via the static server).

---

## Architecture & Data Flow

Veil processes every document strictly in volatile browser memory along a unidirectional pipeline:

1. **Input (`main.js` / `export.js`)**: User pastes text into the `<textarea>`, loads the synthetic sample, or drops/uploads a validated `.txt`/`.csv` file via the `FileReader` API. Input edits are debounced (`120 ms`) and wrapped in `try/catch`.
2. **Detect (`detectors.js`)**: Six independent detectors scan the raw string and emit candidate spans `{ type, start, end, value, note }`:
   - `detectCreditCards` validates 13–19 digit candidates with `validateLuhn()`.
   - `detectEmails` matches RFC-style addresses (case-insensitive).
   - `detectAadhaar` matches 12-digit sequences starting `2–9` (labelled shape-only, with an optional `validateVerhoeff()` checksum indicator).
   - `detectPAN` matches `[A-Z]{5}[0-9]{4}[A-Z]` on word boundaries.
   - `detectIPv4` validates four dot-separated octets in `0–255` and rejects embedded version strings.
   - `detectPhoneNumbers` matches Indian mobile formats (`+91`/`91` optional prefix, 10 digits starting `6–9`) using lookarounds to avoid longer numeric strings.
3. **Resolve Overlaps (`classifyEntities` in `detectors.js`)**: Candidates are sorted by strict priority (`card > email > aadhaar > pan > ipv4 > phone`), then longer span, then start index. Non-overlapping spans are kept greedily via binary search and returned sorted by `start`.
4. **Redact (`redact.js`)**: `applyRedaction(text, spans, mode)` slices the original string between classified spans—preserving all surrounding whitespace and `\r\n`/`\n` line breaks verbatim—and substitutes each span using `redactFull`, `redactPartial`, or `pseudonymize` (whose in-memory normalization map is created and discarded per run).
5. **Render & Audit (`main.js` / `audit.js`)**: `DocumentFragment` builds the Original and Sanitized diff views exclusively with `createTextNode` and `<span>` elements (with entity color coding and `type + validation note` tooltips). `generateAuditSummary()` updates counters and session status using counts/metadata only.
6. **Export (`export.js`)**: `downloadSanitizedFile()` writes **only** `sanitizedText` to a `Blob` and revokes the Object URL after triggering the download; `copy()` writes **only** `sanitizedText` to the clipboard.

---

## Known Limitations

- **Pattern-Based Detection Only**: Regex and checksum rules can miss context-dependent PII and cannot guarantee complete anonymity or legal/regulatory compliance (e.g., GDPR, HIPAA, DPDP).
- **No Name or Physical Address Detection**: Unstructured free-text entities such as person names, street addresses, job titles, or custom internal secrets are not detected without NLP/NER models.
- **Aadhaar Shape-Only Matching**: Any 12-digit number starting with `2–9` matches the Aadhaar pattern even if it is an arbitrary identifier; Verhoeff checksum status is surfaced as a confidence note rather than a hard filter.
- **India-Focused Financial & Telecom Formats**: Phone (`+91`/`6–9`), PAN, and Aadhaar rules target Indian formats; international phone formats or non-Indian national IDs are outside MVP scope.
- **Plain-Text CSV Handling**: CSV files are processed as raw text preserving delimiters and line structure; malformed quoting or multi-line CSV cells with embedded newlines are treated as plain text lines.

---

## 2-Minute Hackathon Pitch Script

**[0:00 – 0:25] The Problem**
"Every day, engineers, analysts, and support teams paste customer logs, CSV exports, and incident tickets straight into cloud tools and LLMs—accidentally leaking emails, phone numbers, PANs, Aadhaar numbers, and credit card numbers. Once sensitive data crosses a network boundary, you can't take it back."

**[0:25 – 0:55] Introducing Veil**
"Meet **Veil**—a privacy-first PII sanitizer that runs **100% inside the browser**. There is no backend, no external API, no analytics, and no persistent storage. Even the fonts are system fonts so zero third-party network requests ever happen. Your sensitive data literally never leaves the tab."

**[0:55 – 1:30] Live Demo Walkthrough**
"Let's load our synthetic dataset—or drop in a local `.txt` or `.csv` file. Instantly, Veil detects and classifies six entity types in memory: credit cards validated with Luhn's algorithm so fake numbers like `4111...1112` are ignored, Aadhaar-shaped IDs with a Verhoeff checksum indicator, PANs, IPv4 addresses (rejecting invalid octets like `999.12.4.1` and version strings), emails, and Indian mobile numbers—all while ignoring dates and order IDs.

Watch the side-by-side diff as we switch modes live: **Full Mask** wipes everything to `[REDACTED]`, **Partial Mask** preserves safe suffixes like `XXXX-XXXX-XXXX-1111`, and **Pseudonymize** normalizes `+91 98765-43210` and `9876543210` to the same `PHONE_01` token so downstream analysis still works—without ever storing or exporting the mapping table."

**[1:30 – 2:00] Security Architecture & Close**
"Under the hood, every highlight is rendered safely with `textContent`—never `innerHTML`—and exports write only the sanitized Blob before revoking the object URL. Veil is honest about what regex can and can't catch, requires zero installation, and runs offline on any laptop. Keep your secrets on your side of the glass—with Veil."
