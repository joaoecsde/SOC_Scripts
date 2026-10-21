"""Helper package for email_header_analyser.py.

Each module handles one stage of the analysis so no single file grows too
large. The entry point only needs ``pipeline.analyse_message()``; the other
modules are imported by the pipeline.

Modules:
    config       Tunable lists (brands, TLDs, extensions...) and scoring settings.
    utils        Small shared helpers: defanging, domains, IPs, safe printing.
    loader       Reads the input and rejects things that are not an email.
    headers      Key headers, Received chain and originating IP.
    auth         SPF / DKIM / DMARC results and domain alignment.
    links        Link extraction from the body and per-link checks.
    attachments  Hashing and static checks on attachments (never executed).
    rules        Turns the facts above into scored findings.
    online       Optional AbuseIPDB / VirusTotal lookups.
    pipeline     Runs every stage in order and returns one result dict.
    report       Terminal report and JSON export.
"""

__version__ = "2.0.0"
