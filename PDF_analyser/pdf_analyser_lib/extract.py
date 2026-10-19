"""Extraction of strings, JavaScript, actions, triggers and embedded files.

Everything is read through ``PdfObject.get`` / ``stream`` (pdf_parser does the
tokenising and filtering). Extracted content is only decoded, never executed.
All ``find_*`` functions return plain dicts so they serialise to JSON.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .parser import ParsedPdf, PdfObject, pdf_parser

ACTION_TYPES = ("/URI", "/SubmitForm", "/GoToR", "/Launch")
# Actions that make an automatic trigger HIGH (the same set rules.py grades).
_ACTIVE_ACTIONS = ("/JavaScript",) + ACTION_TYPES
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}


def _bytes_to_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def decode_pdf_string(tokens: Optional[List[str]]) -> str:
    """Decode a PDF literal ``( )`` or hex ``< >`` string token list.

    Args:
        tokens: pdf_parser token list for the value.

    Returns:
        The decoded text (UTF-16BE if a BOM is present, else latin-1), or
        an empty string if the tokens are not a string.
    """
    if not tokens or not isinstance(tokens, list) or any(not isinstance(t, str) for t in tokens):
        return ""
    text = "".join(tokens).strip()
    if text.startswith("(") and text.endswith(")"):
        body = text[1:-1]
        out = bytearray()
        i = 0
        while i < len(body):
            ch = body[i]
            if ch != "\\" or i + 1 >= len(body):
                out += ch.encode("latin-1", "replace")
                i += 1
                continue
            nxt = body[i + 1]
            if nxt in _ESCAPES:
                out += _ESCAPES[nxt].encode()
                i += 2
            elif nxt in "01234567":
                m = re.match(r"[0-7]{1,3}", body[i + 1:])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
            elif nxt == "\r":
                i += 3 if body[i + 2:i + 3] == "\n" else 2
            elif nxt == "\n":
                i += 2
            else:  # \( \) \\ and unknown escapes: the character itself
                out += nxt.encode("latin-1", "replace")
                i += 2
        return _bytes_to_text(bytes(out))
    if text.startswith("<") and not text.startswith("<<") and text.endswith(">"):
        digits = re.sub(r"\s+", "", text[1:-1])
        if len(digits) % 2:
            digits += "0"
        try:
            return _bytes_to_text(bytes.fromhex(digits))
        except ValueError:
            return ""
    return ""


def ref_ids(tokens: Optional[List[str]]) -> List[int]:
    """Return the ``N`` of every ``N G R`` triple in a token list."""
    if not isinstance(tokens, list):
        return []
    flat = [t for t in tokens if isinstance(t, str) and t.strip()]
    if flat and flat[0].strip()[0] in "(<":   # a string, not a reference
        return []
    return [int(flat[i - 2]) for i in range(2, len(flat))
            if flat[i] == "R" and flat[i - 2].isdigit() and flat[i - 1].isdigit()]


def _is_dict(value) -> bool:
    return isinstance(value, list) and bool(value) and isinstance(value[0], tuple)


def _items(obj: PdfObject) -> list:
    """Top-level (key, tokens) pairs of the object's dictionary."""
    return obj.items()


def _segments(items):
    """Split a parsed dict into runs of unique keys.

    pdf_parser flattens dicts that sit inside arrays: the second dict of
    ``[<< A >> << B >>]`` is merged into the parent, so the parent can hold
    two ``/S`` keys. A real PDF dict never repeats a key, so a repeat starts
    a new segment and each merged action is still seen on its own.
    """
    seg, keys = [], set()
    for k, v in items:
        if k in keys:
            yield seg
            seg, keys = [], set()
        seg.append((k, v))
        keys.add(k)
    if seg:
        yield seg


def _walk_dicts(items):
    """Yield every dict nested anywhere in ``items`` (``items`` included).

    Iterative (no recursion), so hostile nesting depth cannot crash it.
    Dicts inside arrays are reached too, because pdf_parser stores them as
    dict values. Each dict is yielded per segment (see ``_segments``).
    """
    stack = [items] if _is_dict(items) else []
    while stack:
        d = stack.pop()
        yield from _segments(d)
        stack.extend(reversed([v for _, v in d if _is_dict(v)]))


def _lookup(items, key: str):
    for k, v in items or []:
        if pdf_parser.EqualCanonical(k, key):
            return v
    return None


def _name(tokens) -> Optional[str]:
    if isinstance(tokens, list):
        for t in tokens:
            if isinstance(t, str) and t.strip():
                return pdf_parser.Canonicalize(t.strip()) if t.startswith("/") else None
    return None


def _resolve(pdf: ParsedPdf, value):
    """Return (items, target_object) for a dict value, a ref to an object, or neither."""
    if _is_dict(value):
        return value, None
    ids = ref_ids(value)
    if len(ids) == 1 and ids[0] in pdf.objects and not _is_array(value):
        return _items(pdf.objects[ids[0]]), ids[0]
    return None, None


def _is_array(value) -> bool:
    return isinstance(value, list) and any(isinstance(t, str) and t.strip() == "[" for t in value)


def _filespec_name(pdf: ParsedPdf, value) -> Optional[str]:
    """Name from a string, an inline filespec dict, or a reference to one."""
    items, _ = _resolve(pdf, value)
    if items is None:
        return decode_pdf_string(value) or None
    for key in ("/UF", "/F"):
        s = decode_pdf_string(_lookup(items, key))
        if s:
            return s
    return None


def find_javascript(pdf: ParsedPdf) -> List[dict]:
    """Find JavaScript held in ``/JS`` entries.

    Returns:
        Dicts ``{"object", "objstm", "source_object", "code"}``, deduplicated
        by ``source_object``.
    """
    results, seen = [], set()
    for oid in sorted(pdf.objects):
        obj = pdf.objects[oid]
        for value in _js_values(_items(obj)):
            ids = ref_ids(value)
            if ids:
                source = ids[0]
                if source in pdf.objects:
                    ref = pdf.objects[source]
                    data = ref.stream()
                    code = _bytes_to_text(data) if data is not None \
                        else decode_pdf_string(_lookup(_items(ref), "/JS"))
                else:
                    code = ""   # dangling reference: keep the entry as evidence
                key = source
            else:
                source, code = oid, decode_pdf_string(value)
                key = (oid, code)   # several inline scripts in one object stay distinct
            if key in seen:
                continue
            seen.add(key)
            results.append({"object": oid, "objstm": obj.objstm, "source_object": source,
                            "code": code})
    return results


def _js_values(items):
    """Yield every ``/JS`` value in a dict, including inline nested dicts and arrays."""
    for d in _walk_dicts(items):
        for k, v in d:
            if pdf_parser.EqualCanonical(k, "/JS"):
                yield v


def find_actions(pdf: ParsedPdf) -> List[dict]:
    """Find URI, SubmitForm, GoToR and Launch actions and their targets.

    Returns:
        Dicts ``{"object", "objstm", "type", "target"}``.
    """
    results, seen = [], set()
    for oid in sorted(pdf.objects):
        obj = pdf.objects[oid]
        for d in _walk_dicts(_items(obj)):   # inline /A, /AA, /Next, arrays ...
            atype = _name(_lookup(d, "/S"))
            if atype not in ACTION_TYPES:
                continue
            if atype == "/URI":
                target = decode_pdf_string(_lookup(d, "/URI"))
            else:
                target = _filespec_name(pdf, _lookup(d, "/F")) or ""
            if (oid, atype, target) in seen:
                continue
            seen.add((oid, atype, target))
            results.append({"object": oid, "objstm": obj.objstm, "type": atype,
                            "target": target})
    return results


def _trigger_action(pdf: ParsedPdf, items, target: Optional[int]) -> Optional[str]:
    """Return a trigger's action type, following its ``/Next`` chain.

    The first active action (JavaScript, URI, SubmitForm, GoToR, Launch)
    found in the action dict, its nested dicts or the ``/Next`` chain
    (dict, reference or array of either) wins; otherwise the action's own
    ``/S``. A visited set stops reference loops.
    """
    seen = {target} if target is not None else set()
    todo = [items]
    while todo:
        for d in _walk_dicts(todo.pop(0)):
            atype = _name(_lookup(d, "/S"))
            if atype in _ACTIVE_ACTIONS:
                return atype
            for rid in ref_ids(_lookup(d, "/Next")):
                if rid in pdf.objects and rid not in seen:
                    seen.add(rid)
                    todo.append(_items(pdf.objects[rid]))
    return _name(_lookup(items, "/S"))


def _document_js(pdf: ParsedPdf, obj: PdfObject) -> List[Optional[int]]:
    """Return where each document-level script lives (object id, or None if inline).

    Walks the ``/Names`` -> ``/JavaScript`` name tree of a Catalog (inline
    or referenced nodes, ``/Kids`` and ``/Names`` arrays). These scripts run
    when the document opens.
    """
    names, _ = _resolve(pdf, _lookup(_items(obj), "/Names"))
    root = _lookup(names, "/JavaScript")
    found: List[Optional[int]] = []
    seen = set()
    todo = [(root, None)]
    while todo:
        value, oid = todo.pop(0)
        if oid is None and not _is_dict(value):   # a reference or an array of them
            refs = ref_ids(value)
            value = None
        else:
            refs = []
        for d in _walk_dicts(value):
            if _lookup(d, "/JS") is not None or _name(_lookup(d, "/S")) == "/JavaScript":
                if oid not in found:
                    found.append(oid)
                continue
            refs += ref_ids(_lookup(d, "/Kids")) + ref_ids(_lookup(d, "/Names"))
        for rid in refs:
            if rid in pdf.objects and rid not in seen:
                seen.add(rid)
                todo.append((_items(pdf.objects[rid]), rid))
    return found


def find_triggers(pdf: ParsedPdf) -> List[dict]:
    """Find ``/OpenAction``, ``/AA`` and document-level JavaScript triggers.

    Returns:
        Dicts ``{"object", "objstm", "keyword", "action", "target_object"}``.
        ``action`` is the ``/S`` name (or the first active action in its
        ``/Next`` chain), or None for a destination array. ``/AA`` yields one
        dict per sub-entry. JavaScript in the Catalog's ``/Names`` ->
        ``/JavaScript`` tree yields ``keyword`` ``/Names`` and ``action``
        ``/JavaScript``, one dict per script location.
    """
    results = []
    for oid in sorted(pdf.objects):
        obj = pdf.objects[oid]
        for keyword in ("/OpenAction", "/AA"):
            value = obj.get(keyword)
            if value is None:
                continue
            if keyword == "/OpenAction":
                entries = [value]
            else:
                container, _ = _resolve(pdf, value)
                entries = [v for _, v in container] if container else []
            for entry in entries:
                items, target = _resolve(pdf, entry)
                action = _trigger_action(pdf, items, target) if items is not None else None
                results.append({"object": oid, "objstm": obj.objstm, "keyword": keyword,
                                "action": action, "target_object": target})
        for target in _document_js(pdf, obj):
            results.append({"object": oid, "objstm": obj.objstm, "keyword": "/Names",
                            "action": "/JavaScript", "target_object": target})
    return results


def find_embedded_files(pdf: ParsedPdf) -> List[dict]:
    """Find embedded file streams (``/Type /EmbeddedFile`` or filespec ``/EF``).

    Filespecs are found at any depth (e.g. inline in a ``/Names`` array).

    Returns:
        Dicts ``{"object", "objstm", "name", "data"}``.
    """
    names: Dict[int, Optional[str]] = {}
    for oid in sorted(pdf.objects):
        for d in _walk_dicts(_items(pdf.objects[oid])):
            ef = _lookup(d, "/EF")
            if ef is None:
                continue
            name = _filespec_name(pdf, [("/UF", _lookup(d, "/UF")), ("/F", _lookup(d, "/F"))])
            ef_items, _ = _resolve(pdf, ef)
            for _, v in ef_items or []:
                for sid in ref_ids(v):
                    names.setdefault(sid, name)
    results = []
    for oid in sorted(pdf.objects):
        obj = pdf.objects[oid]
        if oid not in names and not pdf_parser.EqualCanonical(obj.type(), "/EmbeddedFile"):
            continue
        data = obj.stream()
        if data is None:
            continue
        results.append({"object": oid, "objstm": obj.objstm, "name": names.get(oid),
                        "data": data})
    return results


def find_keywords(pdf: ParsedPdf) -> Dict[str, List[int]]:
    """Map ``/RichMedia``, ``/ObjStm`` and ``/XObject`` to the objects containing them."""
    out = {"/RichMedia": [], "/ObjStm": [], "/XObject": []}
    for oid in sorted(pdf.objects):
        for name in out:
            if pdf.objects[oid].has_name(name):
                out[name].append(oid)
    return out


def find_richmedia_streams(pdf: ParsedPdf) -> List[dict]:
    """Return streams referenced one level deep from ``/RichMedia`` objects."""
    results, seen = [], set()
    for oid in sorted(pdf.objects):
        if not pdf.objects[oid].has_name("/RichMedia"):
            continue
        for rid in pdf.objects[oid].refs():
            if rid in seen or rid == oid or rid not in pdf.objects:
                continue
            data = pdf.objects[rid].stream()
            if data is None:
                continue
            seen.add(rid)
            results.append({"object": rid, "objstm": pdf.objects[rid].objstm, "data": data})
    return results
