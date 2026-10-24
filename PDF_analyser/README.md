# PDF Static Analyser

A Python tool that triages a suspicious **PDF** without opening it. It looks for active content (JavaScript, auto-run actions, embedded files, launch and form-submit actions) and gives a **LOW / MEDIUM / HIGH** verdict with the reasons behind it. It works **offline** and never executes anything from the file.


## Requirements

- Python 3.8 or newer
- No third-party packages. Parsing uses Didier Stevens' [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/), vendored in `vendor/pdf_parser.py` and kept unmodified.


## What It Detects

- JavaScript (`/JS`, `/JavaScript`), including scripts inside object streams and hex-escaped names such as `/J#53`
- Automatic triggers: `/OpenAction` (following its `/Next` chain), `/AA` (additional actions) and document-level JavaScript in the Catalog `/Names` tree
- Actions: `/URI`, `/Launch`, `/SubmitForm`, `/GoToR`, `/GoToE`, `/ImportData`
- Embedded files (`/EmbeddedFile`), including executables and scripts by name or by `MZ` / `#!` prefix
- Rich media (`/RichMedia`) and XFA forms (`/XFA`)
- Obfuscation markers in JavaScript: `eval`, `unescape`, `String.fromCharCode`, `%u` shellcode, long hex strings, heavy string building
- Encrypted or malformed files: the report says when parsing was partial or the verdict may be understated


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


## Running the Script

Run it from the `PDF_analyser` folder (the script finds its package next to it).

```bash
python3 pdf_analyser.py suspicious.pdf                  # terminal report only
python3 pdf_analyser.py suspicious.pdf -out             # + report.txt and payloads.zip (password: infected)
python3 pdf_analyser.py suspicious.pdf --json           # + JSON_report.json
python3 pdf_analyser.py suspicious.pdf -out --json      # both, in the same folder
python3 pdf_analyser.py suspicious.pdf --exit-code      # for scripts
```

| Flag | Description |
|---|---|
| `input` | Path to the PDF (needs `%PDF-` in its first 1024 bytes) |
| `-out` | Save `report.txt`, and every extracted script / file in `payloads.zip` (password `infected`), to the results folder. Needs the `zip` command (standard on macOS and Linux) |
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


## Analysis Workflow

What happens when `python3 pdf_analyser.py suspicious.pdf` runs. The PDF is only ever **read as bytes** (`open(path, "rb")`). It is never rendered, never handed to a PDF reader or any other program, and nothing inside it is executed.

```
pdf_analyser.py: build_parser()     parse CLI flags     bad flag -------> exit 3
      |
      v
pdf_analyser.py: check_pdf()        first 1024 bytes need %PDF-
      |                             missing / unreadable / not a PDF --> exit 3
      v
output.py: payload_stage()          -out only: temporary .payloads-* folder in
      |                             pdf-analysis-results/, removed on exit; an
      |                             error is only reported after the verdict
      v
pipeline.py: analyse_pdf()          read all bytes: size + SHA-256
      |                             any exception ("analysis failed") -> exit 3
      v
parser.py: load_pdf()               bytes in memory -> vendored pdf_parser
      |                             every indirect object, every copy
      |                             /ObjStm expanded, /Encrypt detected
      |                             problems -> errors (partial), run continues
      v
extract.py: iter_javascript()       /JS strings and streams
extract.py: iter_embedded_files()   /EmbeddedFile, filespec /EF
extract.py: iter_richmedia_streams()
                                    streams under /RichMedia
      |                             one stream at a time: graded
      |                             (rules.javascript_finding / embedded_finding),
      |                             hashed and, with -out, written to the staging
      |                             folder (output.PayloadStage), then dropped
      v
extract.py: find_actions()          /URI /Launch /SubmitForm /GoToR /GoToE /ImportData
extract.py: find_triggers()         /OpenAction + /Next chain, /AA, /Names JavaScript
extract.py: find_keywords()         /RichMedia /XFA /ObjStm /XObject
extract.py: find_duplicates()       object ids defined more than once
      |
      v
rules.py: trigger_findings(),       remaining facts -> high / medium / info
          other_findings()          findings, in the same order as evaluate()
      |
      v
rules.py: verdict()                 HIGH / MEDIUM / LOW
      |
      v
report.py: print_report()           safe() + defang_text() on every PDF value
      |
      v
-out or --json given? -- no -----------------------------------------+
      | yes                                                          |
      v                                                              |
output.py: make_run_dir()           new DD-MM-YYYY-<name> folder     |
      |                                                              |
      +--> -out:   output.py: write_outputs()                        |
      |            report.txt (defanged), and the staged             |
      |            payloads zipped into payloads.zip: scripts        |
      |            .js.txt, files .bin (pw: infected), names         |
      |            reduced to A-Za-z0-9._-                           |
      |                                                              |
      +--> --json: report.py: save_json()                            |
      |            raw values, payloads -> size + SHA-256            |
      |            + payload_name (null without -out or not staged)  |
      |            (both run when both flags are given)              |
      |                                                              |
      |            write failed ("cannot write results")             |
      |            -------------------------------------> exit 3     |
      |            payloads not staged ("cannot save payloads"):     |
      |            report.txt / JSON still written, no zip           |
      |            -------------------------------------> exit 3     |
      v                                                              |
--exit-code given? (pdf_analyser.py: main()) <-----------------------+
      |
      +-- yes --> exit 0 / 1 / 2 for LOW / MEDIUM / HIGH
      +-- no  --> exit 0
```

### Step by step

1. **Command line** (`pdf_analyser.py`): flags are parsed. A bad flag exits with 3, not 2, so it cannot be mistaken for a HIGH verdict.
2. **Input check** (`check_pdf`): the first 1024 bytes are read and must contain `%PDF-`. Missing, unreadable or non-PDF files stop here with exit 3.
3. **Hashing** (`pipeline.analyse_pdf`): the whole file is read as bytes to record its size and SHA-256.
4. **Parsing** (`parser.load_pdf`): the bytes are wrapped in an in-memory buffer and fed to the vendored `pdf_parser`, so its URL and ZIP input paths are never used. Every indirect object is kept, including every copy of a repeated object number. `/ObjStm` object streams are decompressed and their objects added. `/Encrypt` in the trailer or an xref stream marks the file as encrypted. Any parse problem is recorded in `errors` (the result becomes `partial`) instead of stopping the run.
5. **Extraction** (`extract.py`): each `find_*` / `iter_*` function walks every copy of every object, including dictionaries nested inline or inside arrays, and resolves `N G R` references to every copy of the target. Strings are decoded (literal, hex, UTF-16BE) and streams are decompressed by `pdf_parser`'s filters. Results are plain dicts: scripts, actions and targets, triggers and the action they reach, embedded file bytes and names, keywords, rich-media streams, duplicate objects. Scripts, embedded files and rich-media streams come from the `iter_*` generators and are handled one at a time: each is graded, hashed and (with `-out`) written to the staging folder, then its bytes are dropped, so memory does not grow with the number of streams.
6. **Rules** (`rules.py`): each fact becomes a finding with a severity (see [Verdict](#verdict)). Scripts and embedded files are graded as they are extracted (`javascript_finding`, `embedded_finding`), the other facts afterwards (`trigger_findings`, `other_findings`); the findings keep the order of `rules.evaluate()`. Scripts are matched with the regexes in `config.JS_MARKERS`; they are searched as text, never run.
7. **Verdict** (`rules.verdict`): HIGH if any high finding, else MEDIUM if any medium, else LOW.
8. **Terminal report** (`report.print_report`): every value taken from the PDF goes through `safe()` (control and bidi characters made visible) and `defang_text()` (`hxxp`, `[.]`), and line breaks are shown as `\n`, so a value cannot fake a report line. It prints before anything is written, so the verdict is shown even if saving fails.
9. **Saved results** (only with `-out` / `--json`): a new run folder is created (see [Output Folder](#output-folder)). `-out` writes the defanged `report.txt`, and zips the staged payloads as inert `.js.txt` / `.bin` bytes into `payloads.zip` (password `infected`). `--json` writes the raw, non-defanged result with each payload replaced by its size, SHA-256 and `payload_name` (its file name inside `payloads.zip`, or `null` without `-out` or when it could not be staged).
10. **Exit**: 0, or 0/1/2 for LOW/MEDIUM/HIGH with `--exit-code`. Any unexpected exception during analysis is caught and reported as `analysis failed` with exit 3, without a traceback.

## Output Folder

With `-out` and/or `--json`, a run folder is created in `pdf-analysis-results/` at the **repo root** (resolved from the script location, not the current directory; the folder is gitignored):

```
pdf-analysis-results/
└── 19-10-2026-suspicious/            DD-MM-YYYY-<pdf name>
    ├── report.txt                    defanged report (-out)
    ├── JSON_report.json              raw results (--json)
    └── payloads.zip                  password "infected" (-out, only if something was extracted)
        ├── obj12_javascript.js.txt       each script
        └── obj7_embedded_invoice.exe.bin each embedded file
```

- Same-day reruns on the same name get `-2`, `-3` and so on.
- Payloads only exist inside the password-protected `payloads.zip` (the usual `infected` convention), so nobody opens one by accident. While the PDF is analysed, each payload is written as soon as it is decoded to a temporary `.payloads-*` folder inside `pdf-analysis-results/`, which is removed once they are zipped. To look at them: `unzip -P infected payloads.zip -d <folder on your analysis machine>`.
- Scripts are always saved as `.js.txt` and everything else as `.bin`, so nothing can be double-clicked and run.
- File names from inside the PDF are reduced to `[A-Za-z0-9._-]` and never leave the run folder.


## Safety Notes

- Fully **offline**: no network access of any kind.
- **JavaScript is never executed.** Scripts are decoded and written as text only; embedded files are written as bytes only, both inside a password-protected zip.
- Each decoded stream is capped at 64 MB (`MAX_STREAM_BYTES` in `config.py`), so a decompression bomb cannot exhaust memory. Streams are analysed one at a time and their bytes are not kept afterwards (only size and SHA-256), so memory stays bounded (a few hundred MB at most) however many streams the file has, and every stream is still analysed. A stream cut at the cap is listed under "Parsing was partial". So is a truncated or corrupt compressed stream, which is decoded as far as it goes.
- Terminal output and `report.txt` are defanged (`hxxp`, `[.]`) and stripped of control characters. JSON keeps raw values, so handle it with care.
- The vendored `vendor/pdf_parser.py` is not modified. Detection uses its canonical name matching, so `/J#53` still counts as `/JS`.
- Still, analyse suspicious files in an isolated machine and treat extracted files as malware.


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


## Tests

From the `PDF_analyser` folder:

```bash
python3 -m unittest discover tests -v
```

Tests build tiny PDFs in memory (no sample files or network). The CLI tests with `-out` / `--json` write a uniquely named run folder under `pdf-analysis-results/` and remove it afterwards.


## Known Limitations

- Static analysis only: heavily obfuscated, encrypted or malformed PDFs can hide content (the report flags encrypted and partially parsed files).
- Encrypted or partially parsed PDFs still get a verdict, built only from what could be parsed, so it may be understated. Automation that relies on `--exit-code` should also check `partial` and `encrypted` in `JSON_report.json` (use `--json`) and send those files for manual review.
- Decoded streams are cut at 64 MB. Content past the cut is not analysed.
- Streams using `/LZWDecode` or `/RunLengthDecode` are analysed as raw (still encoded) bytes, because the vendored pdf-parser returns their decoded output in a form the tool does not use.
- Some dictionaries inside arrays are read imperfectly by the vendored pdf-parser; the tool still looks inside them, but an unusual layout can hide a value (for example a reference placed right after an inline dictionary in an array).
- JavaScript is matched against a short list of obfuscation markers, not deobfuscated.
- A LOW verdict does not prove a file is safe.
