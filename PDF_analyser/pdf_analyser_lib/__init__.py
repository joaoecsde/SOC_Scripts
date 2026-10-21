"""Helper package for pdf_analyser.py.

Each module handles one stage of the analysis. The entry point only needs
``pipeline.analyse_pdf()``; the other modules are imported by the pipeline.

Modules:
    config       Tunable lists and thresholds.
    utils        Small shared helpers: safe printing, defanging.
    parser       Wraps the vendored pdf_parser and expands /ObjStm objects.
    extract      String decoding; JavaScript, actions, triggers, embedded files.
    rules        Turns the facts above into findings and a verdict.
    pipeline     Runs every stage in order and returns one result.
    report       Terminal report and JSON export.
    output       Run folder and extracted-file writing.
"""

__version__ = "1.0.0"
