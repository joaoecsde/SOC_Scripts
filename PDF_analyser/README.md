# PDF Static Analyser

A Python tool that triages a suspicious **PDF** without opening it. It looks for active content (JavaScript, auto-run actions, embedded files, launch and form-submit actions) and gives a **LOW / MEDIUM / HIGH** verdict with the reasons behind it. It works **offline** and never executes anything from the file.

---

## Requirements

- Python 3.8 or newer
- No third-party packages. Parsing uses Didier Stevens' [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/), vendored in `vendor/pdf_parser.py` and kept unmodified.

---

## What It Detects

- JavaScript (`/JS`, `/JavaScript`), including scripts inside object streams and hex-escaped names such as `/J#53`
- Automatic triggers: `/OpenAction` (following its `/Next` chain), `/AA` (additional actions) and document-level JavaScript in the Catalog `/Names` tree
- Actions: `/URI`, `/Launch`, `/SubmitForm`, `/GoToR`, `/GoToE`, `/ImportData`
- Embedded files (`/EmbeddedFile`), including executables and scripts by name or by `MZ` / `#!` prefix
- Rich media (`/RichMedia`) and XFA forms (`/XFA`)
- Obfuscation markers in JavaScript: `eval`, `unescape`, `String.fromCharCode`, `%u` shellcode, long hex strings, heavy string building
- Encrypted or malformed files: the report says when parsing was partial or the verdict may be understated

---

## Verdict

| Level | Finding |
|---|---|
| HIGH | JavaScript (any action with a `/JS` entry, e.g. `/Rendition`) or a `/Launch`, `/URI`, `/SubmitForm`, `/GoToR`, `/GoToE`, `/ImportData` action that runs automatically: from `/OpenAction` (including its `/Next` chain), an `/AA` document event, or document-level JavaScript in the Catalog `/Names` tree |
| HIGH | JavaScript with obfuscation markers |
| HIGH | Embedded executable or script file |
| HIGH | `/SubmitForm`, `/GoToR` or `/GoToE` to an external target |
| MEDIUM | Plain JavaScript, or JavaScript that could not be resolved |
| MEDIUM | Embedded (non-executable) file |
| MEDIUM | `/Launch`, `/ImportData`, `/RichMedia`, `/XFA` form, local `/SubmitForm`, `/GoToR` or `/GoToE` |
| MEDIUM | An object number defined more than once where a copy holds active content (`/JS`, `/JavaScript`, `/Launch`, `/SubmitForm`, `/GoToR`, `/GoToE`, `/ImportData`, `/EmbeddedFile`) |
| LOW | Nothing above |

Informational only (listed, never raise the verdict): `/ObjStm`, `/XObject`, an object number defined more than once with no active content (normal after an editor saves incrementally), `/URI` links that only open when the reader clicks them (for example a link annotation), and triggers with no active action (for example `/OpenAction` going to a page, which is how most normal PDFs open). A `/URI` action that runs automatically from `/OpenAction` or `/AA` is HIGH (first row above).

Every copy of a repeated object number is analysed. A PDF reader picks one copy through the xref table, which a crafted file can point at an earlier copy than the last one, so no copy is skipped. A reference `N G R` follows every copy of N whatever its generation number, because readers may ignore a mismatch. When an attachment's object has several copies, every copy is extracted, but only copies that look like an attachment get its file name. Findings and extracted file names say which copy they came from: `obj 5, copy 1` and `obj5_copy1_javascript.js.txt` for the object itself, `(obj 5, copy 1)` on a trigger that reached that copy, and `(script in obj 3, copy 1)` / `obj2_javascript_from_obj3_copy1.js.txt` for a script stored in another object.

The verdict is a **heuristic**. Always confirm manually before closing or escalating a case.

---

## Running the Script

Run it from the `PDF_analyser` folder (the script finds its package next to it).

```bash
python3 pdf_analyser.py suspicious.pdf                  # terminal report only
python3 pdf_analyser.py suspicious.pdf -out             # + report.txt and extracted scripts/files
python3 pdf_analyser.py suspicious.pdf --json           # + JSON_report.json
python3 pdf_analyser.py suspicious.pdf -out --json      # both, in the same folder
python3 pdf_analyser.py suspicious.pdf --exit-code      # for scripts
```

| Flag | Description |
|---|---|
| `input` | Path to the PDF (needs `%PDF-` in its first 1024 bytes) |
| `-out` | Save `report.txt` and every extracted script / file to the results folder |
| `--json` | Save `JSON_report.json` (raw values, not defanged) to the results folder |
| `--exit-code` | Exit with 0/1/2 for LOW/MEDIUM/HIGH |
| `--version` | Show the version |

### Exit codes

| Exit code | Meaning |
|---|---|
| 0 | Finished (LOW verdict when `--exit-code` is used) |
| 1 | MEDIUM verdict (`--exit-code` only) |
| 2 | HIGH verdict (`--exit-code` only) |
| 3 | Error: file missing or unreadable, not a PDF, results not writable |

---

## Output Folder

With `-out` and/or `--json`, a run folder is created in `pdf-analysis-results/` at the **repo root** (resolved from the script location, not the current directory; the folder is gitignored):

```
pdf-analysis-results/
└── 19-10-2026-suspicious/            DD-MM-YYYY-<pdf name>
    ├── report.txt                    defanged report (-out)
    ├── JSON_report.json              raw results (--json)
    ├── obj12_javascript.js.txt       each script (-out)
    └── obj7_embedded_invoice.exe.bin each embedded file (-out)
```

- Same-day reruns on the same name get `-2`, `-3` and so on.
- Scripts are always saved as `.js.txt` and everything else as `.bin`, so nothing can be double-clicked and run.
- File names from inside the PDF are reduced to `[A-Za-z0-9._-]` and never leave the run folder.

---

## Safety Notes

- Fully **offline**: no network access of any kind.
- **JavaScript is never executed.** Scripts are decoded and written as text only; embedded files are written as bytes only.
- Terminal output and `report.txt` are defanged (`hxxp`, `[.]`) and stripped of control characters. JSON keeps raw values, so handle it with care.
- The vendored `vendor/pdf_parser.py` is not modified. Detection uses its canonical name matching, so `/J#53` still counts as `/JS`.
- Still, analyse suspicious files in an isolated machine and treat extracted files as malware.

---

## File Layout

```
PDF_analyser/
├── pdf_analyser.py          command line only
├── vendor/pdf_parser.py     Didier Stevens pdf-parser (unmodified)
├── pdf_analyser_lib/
│   ├── config.py     lists and thresholds
│   ├── utils.py      colours, safe printing, defanging
│   ├── parser.py     pdf_parser wrapper, /ObjStm expansion
│   ├── extract.py    JavaScript, actions, triggers, embedded files
│   ├── rules.py      findings and verdict
│   ├── pipeline.py   runs every stage (analyse_pdf)
│   ├── report.py     terminal report and JSON
│   └── output.py     run folder and extracted files
└── tests/
```

---

## Tests

From the `PDF_analyser` folder:

```bash
python3 -m unittest discover tests -v
```

Tests build tiny PDFs in memory (no sample files or network). The CLI tests with `-out` / `--json` write a uniquely named run folder under `pdf-analysis-results/` and remove it afterwards.

---

## Known Limitations

- Static analysis only: heavily obfuscated, encrypted or malformed PDFs can hide content (the report flags encrypted and partially parsed files).
- Encrypted or partially parsed PDFs still get a verdict, built only from what could be parsed, so it may be understated. Automation that relies on `--exit-code` should also check `partial` and `encrypted` in `JSON_report.json` (use `--json`) and send those files for manual review.
- There is no size cap on stream decompression: a crafted stream (a "zip bomb") can make the tool use a lot of memory. Run it on an analysis machine, not on a shared server.
- Some dictionaries inside arrays are read imperfectly by the vendored pdf-parser; the tool still looks inside them, but an unusual layout can hide a value (for example a reference placed right after an inline dictionary in an array).
- JavaScript is matched against a short list of obfuscation markers, not deobfuscated.
- A LOW verdict does not prove a file is safe.
